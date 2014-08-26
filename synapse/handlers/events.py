# -*- coding: utf-8 -*-
# Copyright 2014 matrix.org
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

from ._base import BaseHandler

import logging


logger = logging.getLogger(__name__)


class EventStreamHandler(BaseHandler):

    def __init__(self, hs):
        super(EventStreamHandler, self).__init__(hs)

        # Count of active streams per user
        self._streams_per_user = {}
        # Grace timers per user to delay the "stopped" signal
        self._stop_timer_per_user = {}

        self.distributor = hs.get_distributor()
        self.distributor.declare("started_user_eventstream")
        self.distributor.declare("stopped_user_eventstream")

        self.clock = hs.get_clock()

        self.notifier = hs.get_notifier()

    @defer.inlineCallbacks
    def get_stream(self, auth_user_id, pagin_config, timeout=0):
        auth_user = self.hs.parse_userid(auth_user_id)

        if pagin_config.from_token is None:
            pagin_config.from_token = None

        events, tokens = yield self.notifier.get_events_for(auth_user, pagin_config, timeout)

        chunk = {
            "chunk": [e.get_dict() for e in events],
            "start_token": tokens[0].to_string(),
            "end_token": tokens[1].to_string(),
        }

        defer.returnValue(chunk)

