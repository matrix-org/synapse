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

from twisted.internet import defer

from .httppusher import HttpPusher
from synapse.push import PusherConfigException
from synapse.util.logcontext import preserve_fn

import logging

logger = logging.getLogger(__name__)


class PusherPool:
    def __init__(self, _hs):
        self.hs = _hs
        self.store = self.hs.get_datastore()
        self.clock = self.hs.get_clock()
        self.pushers = {}
        self.last_pusher_started = -1

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
        self._create_pusher({
            "user_name": user_id,
            "kind": kind,
            "app_id": app_id,
            "app_display_name": app_display_name,
            "device_display_name": device_display_name,
            "pushkey": pushkey,
            "ts": time_now_msec,
            "lang": lang,
            "data": data,
            "last_token": None,
            "last_success": None,
            "failing_since": None
        })
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
    def remove_pushers_by_user(self, user_id, except_token_ids=[]):
        all = yield self.store.get_all_pushers()
        logger.info(
            "Removing all pushers for user %s except access tokens ids %r",
            user_id, except_token_ids
        )
        for p in all:
            if p['user_name'] == user_id and p['access_token'] not in except_token_ids:
                logger.info(
                    "Removing pusher for app id %s, pushkey %s, user %s",
                    p['app_id'], p['pushkey'], p['user_name']
                )
                yield self.remove_pusher(p['app_id'], p['pushkey'], p['user_name'])

    def _create_pusher(self, pusherdict):
        if pusherdict['kind'] == 'http':
            return HttpPusher(
                self.hs,
                user_id=pusherdict['user_name'],
                app_id=pusherdict['app_id'],
                app_display_name=pusherdict['app_display_name'],
                device_display_name=pusherdict['device_display_name'],
                pushkey=pusherdict['pushkey'],
                pushkey_ts=pusherdict['ts'],
                data=pusherdict['data'],
                last_token=pusherdict['last_token'],
                last_success=pusherdict['last_success'],
                failing_since=pusherdict['failing_since']
            )
        else:
            raise PusherConfigException(
                "Unknown pusher type '%s' for user %s" %
                (pusherdict['kind'], pusherdict['user_name'])
            )

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
        logger.info("Starting %d pushers", len(pushers))
        for pusherdict in pushers:
            try:
                p = self._create_pusher(pusherdict)
            except PusherConfigException:
                logger.exception("Couldn't start a pusher: caught PusherConfigException")
                continue
            if p:
                fullid = "%s:%s:%s" % (
                    pusherdict['app_id'],
                    pusherdict['pushkey'],
                    pusherdict['user_name']
                )
                if fullid in self.pushers:
                    self.pushers[fullid].stop()
                self.pushers[fullid] = p
                preserve_fn(p.start)()

        logger.info("Started pushers")

    @defer.inlineCallbacks
    def remove_pusher(self, app_id, pushkey, user_id):
        fullid = "%s:%s:%s" % (app_id, pushkey, user_id)
        if fullid in self.pushers:
            logger.info("Stopping pusher %s", fullid)
            self.pushers[fullid].stop()
            del self.pushers[fullid]
        yield self.store.delete_pusher_by_app_id_pushkey_user_id(
            app_id, pushkey, user_id
        )
