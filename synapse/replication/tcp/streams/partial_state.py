# Copyright 2022 The Matrix.org Foundation C.I.C.
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
from typing import TYPE_CHECKING

import attr

from synapse.replication.tcp.streams._base import _StreamFromIdGen

if TYPE_CHECKING:
    from synapse.server import HomeServer


@attr.s(slots=True, frozen=True, auto_attribs=True)
class UnPartialStatedRoomStreamRow:
    # ID of the room that has been un-partial-stated.
    room_id: str


class UnPartialStatedRoomStream(_StreamFromIdGen):
    """
    Stream to notify about rooms becoming un-partial-stated;
    that is, when the background sync finishes such that we now have full state for
    the room.
    """

    NAME = "un_partial_stated_room"
    ROW_TYPE = UnPartialStatedRoomStreamRow

    def __init__(self, hs: "HomeServer"):
        store = hs.get_datastores().main
        super().__init__(
            hs.get_instance_name(),
            store.get_un_partial_stated_rooms_from_stream,
            store._un_partial_stated_rooms_stream_id_gen,
        )


@attr.s(slots=True, frozen=True, auto_attribs=True)
class UnPartialStatedEventStreamRow:
    # ID of the event that has been un-partial-stated.
    event_id: str

    # True iff the rejection status of the event changed as a result of being
    # un-partial-stated.
    rejection_status_changed: bool


class UnPartialStatedEventStream(_StreamFromIdGen):
    """
    Stream to notify about events becoming un-partial-stated.
    """

    NAME = "un_partial_stated_event"
    ROW_TYPE = UnPartialStatedEventStreamRow

    def __init__(self, hs: "HomeServer"):
        store = hs.get_datastores().main
        super().__init__(
            hs.get_instance_name(),
            store.get_un_partial_stated_events_from_stream,
            store._un_partial_stated_events_stream_id_gen,
        )
