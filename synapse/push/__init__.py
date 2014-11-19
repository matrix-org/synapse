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

from synapse.streams.config import PaginationConfig
from synapse.types import StreamToken

import synapse.util.async

import logging

logger = logging.getLogger(__name__)

class Pusher(object):
    INITIAL_BACKOFF = 1000
    MAX_BACKOFF = 10 * 60 * 1000

    def __init__(self, _hs, user_name, app, app_display_name, device_display_name, pushkey, data, last_token):
        self.hs = _hs
        self.evStreamHandler = self.hs.get_handlers().event_stream_handler
        self.store = self.hs.get_datastore()
        self.user_name = user_name
        self.app = app
        self.app_display_name = app_display_name
        self.device_display_name = device_display_name
        self.pushkey = pushkey
        self.data = data
        self.last_token = last_token
        self.backoff_delay = Pusher.INITIAL_BACKOFF

    @defer.inlineCallbacks
    def start(self):
        if not self.last_token:
            # First-time setup: get a token to start from (we can't just start from no token, ie. 'now'
            # because we need the result to be reproduceable in case we fail to dispatch the push)
            config = PaginationConfig(from_token=None, limit='1')
            chunk = yield self.evStreamHandler.get_stream(self.user_name, config, timeout=0)
            self.last_token = chunk['end']
            self.store.update_pusher_last_token(self.user_name, self.pushkey, self.last_token)
            logger.info("Pusher %s for user %s starting from token %s",
                        self.pushkey, self.user_name, self.last_token)

        while True:
            from_tok = StreamToken.from_string(self.last_token)
            config = PaginationConfig(from_token=from_tok, limit='1')
            chunk = yield self.evStreamHandler.get_stream(self.user_name, config, timeout=100*365*24*60*60*1000)

            if (self.dispatchPush(chunk['chunk'][0])):
                self.backoff_delay = Pusher.INITIAL_BACKOFF
                self.last_token = chunk['end']
                self.store.update_pusher_last_token(self.user_name, self.pushkey, self.last_token)
            else:
                logger.warn("Failed to dispatch push for user %s. Trying again in %dms",
                            self.user_name, self.backoff_delay)
                yield synapse.util.async.sleep(self.backoff_delay / 1000.0)
                self.backoff_delay *=2
                if self.backoff_delay > Pusher.MAX_BACKOFF:
                    self.backoff_delay = Pusher.MAX_BACKOFF


class PusherConfigException(Exception):
    def __init__(self, msg):
        super(PusherConfigException, self).__init__(msg)