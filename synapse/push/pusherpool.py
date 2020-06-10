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
from collections import defaultdict
from threading import Lock
from typing import Dict, Tuple, Union

from twisted.internet import defer

from synapse.metrics import LaterGauge
from synapse.metrics.background_process_metrics import run_as_background_process
from synapse.push import PusherConfigException
from synapse.push.emailpusher import EmailPusher
from synapse.push.httppusher import HttpPusher
from synapse.push.pusher import PusherFactory
from synapse.util.async_helpers import concurrently_execute

logger = logging.getLogger(__name__)


class PusherPool:
    """
    The pusher pool. This is responsible for dispatching notifications of new events to
    the http and email pushers.

    It provides three methods which are designed to be called by the rest of the
    application: `start`, `on_new_notifications`, and `on_new_receipts`: each of these
    delegates to each of the relevant pushers.

    Note that it is expected that each pusher will have its own 'processing' loop which
    will send out the notifications in the background, rather than blocking until the
    notifications are sent; accordingly Pusher.on_started, Pusher.on_new_notifications and
    Pusher.on_new_receipts are not expected to return deferreds.
    """

    def __init__(self, _hs):
        self.hs = _hs
        self.pusher_factory = PusherFactory(_hs)
        self._should_start_pushers = _hs.config.start_pushers
        self.store = self.hs.get_datastore()
        self.clock = self.hs.get_clock()

        # map from user id to app_id:pushkey to pusher
        self.pushers = {}  # type: Dict[str, Dict[str, Union[HttpPusher, EmailPusher]]]

        # a lock for the pushers dict, since `count_pushers` is called from an different
        # and we otherwise get concurrent modification errors
        self._pushers_lock = Lock()

        def count_pushers():
            results = defaultdict(int)  # type: Dict[Tuple[str, str], int]
            with self._pushers_lock:
                for pushers in self.pushers.values():
                    for pusher in pushers.values():
                        k = (type(pusher).__name__, pusher.app_id)
                        results[k] += 1
            return results

        LaterGauge(
            name="synapse_pushers",
            desc="the number of active pushers",
            labels=["kind", "app_id"],
            caller=count_pushers,
        )

    def start(self):
        """Starts the pushers off in a background process.
        """
        if not self._should_start_pushers:
            logger.info("Not starting pushers because they are disabled in the config")
            return
        run_as_background_process("start_pushers", self._start_pushers)

    @defer.inlineCallbacks
    def add_pusher(
        self,
        user_id,
        access_token,
        kind,
        app_id,
        app_display_name,
        device_display_name,
        pushkey,
        lang,
        data,
        profile_tag="",
    ):
        """Creates a new pusher and adds it to the pool

        Returns:
            Deferred[EmailPusher|HttpPusher]
        """
        time_now_msec = self.clock.time_msec()

        # we try to create the pusher just to validate the config: it
        # will then get pulled out of the database,
        # recreated, added and started: this means we have only one
        # code path adding pushers.
        self.pusher_factory.create_pusher(
            {
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
                "failing_since": None,
            }
        )

        # create the pusher setting last_stream_ordering to the current maximum
        # stream ordering in event_push_actions, so it will process
        # pushes from this point onwards.
        last_stream_ordering = yield self.store.get_latest_push_action_stream_ordering()

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
        pusher = yield self.start_pusher_by_id(app_id, pushkey, user_id)

        return pusher

    @defer.inlineCallbacks
    def remove_pushers_by_app_id_and_pushkey_not_user(
        self, app_id, pushkey, not_user_id
    ):
        to_remove = yield self.store.get_pushers_by_app_id_and_pushkey(app_id, pushkey)
        for p in to_remove:
            if p["user_name"] != not_user_id:
                logger.info(
                    "Removing pusher for app id %s, pushkey %s, user %s",
                    app_id,
                    pushkey,
                    p["user_name"],
                )
                yield self.remove_pusher(p["app_id"], p["pushkey"], p["user_name"])

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
            if p["access_token"] in tokens:
                logger.info(
                    "Removing pusher for app id %s, pushkey %s, user %s",
                    p["app_id"],
                    p["pushkey"],
                    p["user_name"],
                )
                yield self.remove_pusher(p["app_id"], p["pushkey"], p["user_name"])

    @defer.inlineCallbacks
    def on_new_notifications(self, min_stream_id, max_stream_id):
        if not self.pushers:
            # nothing to do here.
            return

        try:
            users_affected = yield self.store.get_push_action_users_in_range(
                min_stream_id, max_stream_id
            )

            for u in users_affected:
                if u in self.pushers:
                    for p in self.pushers[u].values():
                        p.on_new_notifications(min_stream_id, max_stream_id)

        except Exception:
            logger.exception("Exception in pusher on_new_notifications")

    @defer.inlineCallbacks
    def on_new_receipts(self, min_stream_id, max_stream_id, affected_room_ids):
        if not self.pushers:
            # nothing to do here.
            return

        try:
            # Need to subtract 1 from the minimum because the lower bound here
            # is not inclusive
            updated_receipts = yield self.store.get_all_updated_receipts(
                min_stream_id - 1, max_stream_id
            )
            # This returns a tuple, user_id is at index 3
            users_affected = {r[3] for r in updated_receipts}

            for u in users_affected:
                if u in self.pushers:
                    for p in self.pushers[u].values():
                        p.on_new_receipts(min_stream_id, max_stream_id)

        except Exception:
            logger.exception("Exception in pusher on_new_receipts")

    @defer.inlineCallbacks
    def start_pusher_by_id(self, app_id, pushkey, user_id):
        """Look up the details for the given pusher, and start it

        Returns:
            Deferred[EmailPusher|HttpPusher|None]: The pusher started, if any
        """
        if not self._should_start_pushers:
            return

        resultlist = yield self.store.get_pushers_by_app_id_and_pushkey(app_id, pushkey)

        pusher_dict = None
        for r in resultlist:
            if r["user_name"] == user_id:
                pusher_dict = r

        pusher = None
        if pusher_dict:
            pusher = yield self._start_pusher(pusher_dict)

        return pusher

    @defer.inlineCallbacks
    def _start_pushers(self):
        """Start all the pushers

        Returns:
            Deferred
        """
        pushers = yield self.store.get_all_pushers()

        # Stagger starting up the pushers so we don't completely drown the
        # process on start up.
        yield concurrently_execute(self._start_pusher, pushers, 10)

        logger.info("Started pushers")

    @defer.inlineCallbacks
    def _start_pusher(self, pusherdict):
        """Start the given pusher

        Args:
            pusherdict (dict): dict with the values pulled from the db table

        Returns:
            Deferred[EmailPusher|HttpPusher]
        """
        try:
            p = self.pusher_factory.create_pusher(pusherdict)
        except PusherConfigException as e:
            logger.warning(
                "Pusher incorrectly configured id=%i, user=%s, appid=%s, pushkey=%s: %s",
                pusherdict["id"],
                pusherdict.get("user_name"),
                pusherdict.get("app_id"),
                pusherdict.get("pushkey"),
                e,
            )
            return
        except Exception:
            logger.exception(
                "Couldn't start pusher id %i: caught Exception", pusherdict["id"],
            )
            return

        if not p:
            return

        appid_pushkey = "%s:%s" % (pusherdict["app_id"], pusherdict["pushkey"])

        with self._pushers_lock:
            byuser = self.pushers.setdefault(pusherdict["user_name"], {})
            if appid_pushkey in byuser:
                byuser[appid_pushkey].on_stop()
            byuser[appid_pushkey] = p

        # Check if there *may* be push to process. We do this as this check is a
        # lot cheaper to do than actually fetching the exact rows we need to
        # push.
        user_id = pusherdict["user_name"]
        last_stream_ordering = pusherdict["last_stream_ordering"]
        if last_stream_ordering:
            have_notifs = yield self.store.get_if_maybe_push_in_range_for_user(
                user_id, last_stream_ordering
            )
        else:
            # We always want to default to starting up the pusher rather than
            # risk missing push.
            have_notifs = True

        p.on_started(have_notifs)

        return p

    @defer.inlineCallbacks
    def remove_pusher(self, app_id, pushkey, user_id):
        appid_pushkey = "%s:%s" % (app_id, pushkey)

        byuser = self.pushers.get(user_id, {})

        if appid_pushkey in byuser:
            logger.info("Stopping pusher %s / %s", user_id, appid_pushkey)
            byuser[appid_pushkey].on_stop()
            with self._pushers_lock:
                del byuser[appid_pushkey]

        yield self.store.delete_pusher_by_app_id_pushkey_user_id(
            app_id, pushkey, user_id
        )
