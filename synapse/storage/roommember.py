# Copyright 2014-2016 OpenMarket Ltd
# Copyright 2018 New Vector Ltd
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
from typing import List, Optional, Tuple

import attr

from synapse.types import PersistedEventPosition

logger = logging.getLogger(__name__)


@attr.s(slots=True, frozen=True, weakref_slot=False, auto_attribs=True)
class RoomsForUser:
    room_id: str
    sender: str
    membership: str
    event_id: str
    stream_ordering: int
    room_version_id: str


@attr.s(slots=True, frozen=True, weakref_slot=False, auto_attribs=True)
class GetRoomsForUserWithStreamOrdering:
    room_id: str
    event_pos: PersistedEventPosition


@attr.s(slots=True, frozen=True, weakref_slot=False, auto_attribs=True)
class ProfileInfo:
    avatar_url: Optional[str]
    display_name: Optional[str]


@attr.s(slots=True, frozen=True, weakref_slot=False, auto_attribs=True)
class MemberSummary:
    # A truncated list of (user_id, event_id) tuples for users of a given
    # membership type, suitable for use in calculating heroes for a room.
    members: List[Tuple[str, str]]
    # The total number of users of a given membership type.
    count: int
