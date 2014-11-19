#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright 2014 OpenMarket Ltd
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

from httppusher import HttpPusher
from synapse.push import PusherConfigException

import logging
import json

logger = logging.getLogger(__name__)

class PusherPool:
    def __init__(self, _hs):
        self.hs = _hs
        self.store = self.hs.get_datastore()
        self.pushers = []
        self.last_pusher_started = -1

    def start(self):
        self._pushers_added()

    def add_pusher(self, user_name, kind, app, app_display_name, device_display_name, pushkey, data):
        # we try to create the pusher just to validate the config: it will then get pulled out of the database,
        # recreated, added and started: this means we have only one code path adding pushers.
        self._create_pusher({
            "user_name": user_name,
            "kind": kind,
            "app": app,
            "app_display_name": app_display_name,
            "device_display_name": device_display_name,
            "pushkey": pushkey,
            "data": data,
            "last_token": None
        })
        self._add_pusher_to_store(user_name, kind, app, app_display_name, device_display_name, pushkey, data)

    @defer.inlineCallbacks
    def _add_pusher_to_store(self, user_name, kind, app, app_display_name, device_display_name, pushkey, data):
        yield self.store.add_pusher(user_name=user_name,
                                 kind=kind,
                                 app=app,
                                 app_display_name=app_display_name,
                                 device_display_name=device_display_name,
                                 pushkey=pushkey,
                                 data=json.dumps(data))
        self._pushers_added()

    def _create_pusher(self, pusherdict):
        if pusherdict['kind'] == 'http':
            return HttpPusher(self.hs,
                               user_name=pusherdict['user_name'],
                               app=pusherdict['app'],
                               app_display_name=pusherdict['app_display_name'],
                               device_display_name=pusherdict['device_display_name'],
                               pushkey=pusherdict['pushkey'],
                               data=pusherdict['data'],
                               last_token=pusherdict['last_token']
                               )
        else:
            raise PusherConfigException("Unknown pusher type '%s' for user %s" %
                                        (pusherdict['kind'], pusherdict['user_name']))

    @defer.inlineCallbacks
    def _pushers_added(self):
        pushers = yield self.store.get_all_pushers_after_id(self.last_pusher_started)
        for p in pushers:
            p['data'] = json.loads(p['data'])
        if (len(pushers)):
            self.last_pusher_started = pushers[-1]['id']

        self._start_pushers(pushers)

    def _start_pushers(self, pushers):
        logger.info("Starting %d pushers", (len(pushers)))
        for pusherdict in pushers:
            p = self._create_pusher(pusherdict)
            if p:
                self.pushers.append(p)
                p.start()