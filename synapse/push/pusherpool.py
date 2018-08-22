#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright 2015, 2016 OpenMarket Ltd
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import logging

from twisted.internet import defer

from synapse.metrics.background_process_metrics import run_as_background_process
from synapse.push.pusher import PusherFactory
from synapse.util.logcontext import make_deferred_yieldable, run_in_background

logger = logging.getLogger(__name__)


class PusherPool:
    def __init__(self, _hs):
        self.hs = _hs
        self.pusher_factory = PusherFactory(_hs)
        self.start_pushers = _hs.config.start_pushers
        self.store = self.hs.get_datastore()
        self.clock = self.hs.get_clock()
        self.pushers = {}

    @defer.inlineCallbacks
    def start(self):
        pushers = yield self.store.get_all_pushers()
        self._start_pushers(pushers)

    @defer.inlineCallbacks
    def add_pusher(self, user_id, access_token, kind, app_id,
                   app_display_name, device_display_name, pushkey, lang, data,
                   profile_tag=""):
        time_now_msec = self.clock.time_msec()

        # we try to create the pusher just to validate the config: it
        # will then get pulled out of the database,
        # recreated, added and started: this means we have only one
        # code path adding pushers.
        self.pusher_factory.create_pusher({
            "id": None,
            "user_name": user_id,
            "kind": kind,
            "app_id": app_id,
            "app_display_name": app_display_name,
            "device_display_name": device_display_name,
            "pushkey": pushkey,
            "ts": time_now_msec,
            "lang": lang,
            "data": data,
            "last_stream_ordering": None,
            "last_success": None,
            "failing_since": None
        })

        # create the pusher setting last_stream_ordering to the current maximum
        # stream ordering in event_push_actions, so it will process
        # pushes from this point onwards.
        last_stream_ordering = (
            yield self.store.get_latest_push_action_stream_ordering()
        )

        yield self.store.add_pusher(
            user_id=user_id,
            access_token=access_token,
            kind=kind,
            app_id=app_id,
            app_display_name=app_display_name,
            device_display_name=device_display_name,
            pushkey=pushkey,
            pushkey_ts=time_now_msec,
            lang=lang,
            data=data,
            last_stream_ordering=last_stream_ordering,
            profile_tag=profile_tag,
        )
        yield self._refresh_pusher(app_id, pushkey, user_id)

    @defer.inlineCallbacks
    def remove_pushers_by_app_id_and_pushkey_not_user(self, app_id, pushkey,
                                                      not_user_id):
        to_remove = yield self.store.get_pushers_by_app_id_and_pushkey(
            app_id, pushkey
        )
        for p in to_remove:
            if p['user_name'] != not_user_id:
                logger.info(
                    "Removing pusher for app id %s, pushkey %s, user %s",
                    app_id, pushkey, p['user_name']
                )
                yield self.remove_pusher(p['app_id'], p['pushkey'], p['user_name'])

    @defer.inlineCallbacks
    def remove_pushers_by_access_token(self, user_id, access_tokens):
        """Remove the pushers for a given user corresponding to a set of
        access_tokens.

        Args:
            user_id (str): user to remove pushers for
            access_tokens (Iterable[int]): access token *ids* to remove pushers
                for
        """
        tokens = set(access_tokens)
        for p in (yield self.store.get_pushers_by_user_id(user_id)):
            if p['access_token'] in tokens:
                logger.info(
                    "Removing pusher for app id %s, pushkey %s, user %s",
                    p['app_id'], p['pushkey'], p['user_name']
                )
                yield self.remove_pusher(
                    p['app_id'], p['pushkey'], p['user_name'],
                )

    def on_new_notifications(self, min_stream_id, max_stream_id):
        run_as_background_process(
            "on_new_notifications",
            self._on_new_notifications, min_stream_id, max_stream_id,
        )

    @defer.inlineCallbacks
    def _on_new_notifications(self, min_stream_id, max_stream_id):
        try:
            users_affected = yield self.store.get_push_action_users_in_range(
                min_stream_id, max_stream_id
            )

            deferreds = []

            for u in users_affected:
                if u in self.pushers:
                    for p in self.pushers[u].values():
                        deferreds.append(
                            run_in_background(
                                p.on_new_notifications,
                                min_stream_id, max_stream_id,
                            )
                        )

            yield make_deferred_yieldable(
                defer.gatherResults(deferreds, consumeErrors=True),
            )
        except Exception:
            logger.exception("Exception in pusher on_new_notifications")

    def on_new_receipts(self, min_stream_id, max_stream_id, affected_room_ids):
        run_as_background_process(
            "on_new_receipts",
            self._on_new_receipts, min_stream_id, max_stream_id, affected_room_ids,
        )

    @defer.inlineCallbacks
    def _on_new_receipts(self, min_stream_id, max_stream_id, affected_room_ids):
        try:
            # Need to subtract 1 from the minimum because the lower bound here
            # is not inclusive
            updated_receipts = yield self.store.get_all_updated_receipts(
                min_stream_id - 1, max_stream_id
            )
            # This returns a tuple, user_id is at index 3
            users_affected = set([r[3] for r in updated_receipts])

            deferreds = []

            for u in users_affected:
                if u in self.pushers:
                    for p in self.pushers[u].values():
                        deferreds.append(
                            run_in_background(
                                p.on_new_receipts,
                                min_stream_id, max_stream_id,
                            )
                        )

            yield make_deferred_yieldable(
                defer.gatherResults(deferreds, consumeErrors=True),
            )
        except Exception:
            logger.exception("Exception in pusher on_new_receipts")

    @defer.inlineCallbacks
    def _refresh_pusher(self, app_id, pushkey, user_id):
        resultlist = yield self.store.get_pushers_by_app_id_and_pushkey(
            app_id, pushkey
        )

        p = None
        for r in resultlist:
            if r['user_name'] == user_id:
                p = r

        if p:

            self._start_pushers([p])

    def _start_pushers(self, pushers):
        if not self.start_pushers:
            logger.info("Not starting pushers because they are disabled in the config")
            return
        logger.info("Starting %d pushers", len(pushers))
        for pusherdict in pushers:
            try:
                p = self.pusher_factory.create_pusher(pusherdict)
            except Exception:
                logger.exception("Couldn't start a pusher: caught Exception")
                continue
            if p:
                appid_pushkey = "%s:%s" % (
                    pusherdict['app_id'],
                    pusherdict['pushkey'],
                )
                byuser = self.pushers.setdefault(pusherdict['user_name'], {})

                if appid_pushkey in byuser:
                    byuser[appid_pushkey].on_stop()
                byuser[appid_pushkey] = p
                run_in_background(p.on_started)

        logger.info("Started pushers")

    @defer.inlineCallbacks
    def remove_pusher(self, app_id, pushkey, user_id):
        appid_pushkey = "%s:%s" % (app_id, pushkey)

        byuser = self.pushers.get(user_id, {})

        if appid_pushkey in byuser:
            logger.info("Stopping pusher %s / %s", user_id, appid_pushkey)
            byuser[appid_pushkey].on_stop()
            del byuser[appid_pushkey]
        yield self.store.delete_pusher_by_app_id_pushkey_user_id(
            app_id, pushkey, user_id
        )
