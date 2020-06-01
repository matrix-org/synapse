# -*- coding: utf-8 -*-
# Copyright 2019 The Matrix.org Foundation C.I.C.
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

from synapse.storage.state import StateFilter

MYPY = False
if MYPY:
    import synapse.server

logger = logging.getLogger(__name__)


class SpamCheckerApi(object):
    """A proxy object that gets passed to spam checkers so they can get
    access to rooms and other relevant information.
    """

    def __init__(self, hs: "synapse.server.HomeServer"):
        self.hs = hs

        self._store = hs.get_datastore()

    @defer.inlineCallbacks
    def get_state_events_in_room(self, room_id: str, types: tuple) -> defer.Deferred:
        """Gets state events for the given room.

        Args:
            room_id: The room ID to get state events in.
            types: The event type and state key (using None
                to represent 'any') of the room state to acquire.

        Returns:
            twisted.internet.defer.Deferred[list(synapse.events.FrozenEvent)]:
                The filtered state events in the room.
        """
        state_ids = yield self._store.get_filtered_current_state_ids(
            room_id=room_id, state_filter=StateFilter.from_types(types)
        )
        state = yield self._store.get_events(state_ids.values())
        return state.values()
