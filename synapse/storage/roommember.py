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
from collections import namedtuple

import attr

from synapse.types import PersistedEventPosition

logger = logging.getLogger(__name__)


@attr.s(slots=True, frozen=True, auto_attribs=True)
class RoomsForUser:
    room_id: str
    sender: str
    membership: str
    event_id: str
    stream_ordering: int


@attr.s(slots=True, frozen=True, auto_attribs=True)
class GetRoomsForUserWithStreamOrdering:
    room_id: str
    event_pos: PersistedEventPosition


# We store this using a namedtuple so that we save about 3x space over using a
# dict.
ProfileInfo = namedtuple("ProfileInfo", ("avatar_url", "display_name"))

# "members" points to a truncated list of (user_id, event_id) tuples for users of
# a given membership type, suitable for use in calculating heroes for a room.
# "count" points to the total numberr of users of a given membership type.
MemberSummary = namedtuple("MemberSummary", ("members", "count"))
