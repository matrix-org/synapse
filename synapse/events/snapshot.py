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


class EventSnapshot(object):
    def __init__(self, prev_events, depth, current_state,
                 current_state_group):
        self._prev_events = prev_events
        self._depth = depth
        self._current_state = current_state
        self._current_state_group = current_state_group


class EventCache(object):
    def __init__(self, store):
        self._store = store

        self._cache = {}

    @defer.inlineCallbacks
    def load_event(self, event_id):
        event = self._cache.get(event_id, None)

        if not event:
            event = yield self._store.get_event(
                event_id,
                allow_none=True
            )

            if event:
                self._cache[event_id] = event

        defer.returnValue(event)

    def load_event_from_cache(self, event_id):
        return self._cache.get(event_id, None)

    def add_to_cache(self, *events):
        self._cache.update({
            event.event_id: event
            for event in events
        })


class EventContext(object):

    def __init__(self, current_state=None, auth_events=None):
        self.current_state = current_state
        self.auth_events = auth_events
        self.state_group = None
