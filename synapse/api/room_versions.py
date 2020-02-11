# -*- coding: utf-8 -*-
# Copyright 2019 New Vector Ltd
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
import attr


class EventFormatVersions(object):
    """This is an internal enum for tracking the version of the event format,
    independently from the room version.
    """

    V1 = 1  # $id:server event id format
    V2 = 2  # MSC1659-style $hash event id format: introduced for room v3
    V3 = 3  # MSC1884-style $hash format: introduced for room v4


KNOWN_EVENT_FORMAT_VERSIONS = {
    EventFormatVersions.V1,
    EventFormatVersions.V2,
    EventFormatVersions.V3,
}


class StateResolutionVersions(object):
    """Enum to identify the state resolution algorithms"""

    V1 = 1  # room v1 state res
    V2 = 2  # MSC1442 state res: room v2 and later


class RoomDisposition(object):
    STABLE = "stable"
    UNSTABLE = "unstable"


@attr.s(slots=True, frozen=True)
class RoomVersion(object):
    """An object which describes the unique attributes of a room version."""

    identifier = attr.ib()  # str; the identifier for this version
    disposition = attr.ib()  # str; one of the RoomDispositions
    event_format = attr.ib()  # int; one of the EventFormatVersions
    state_res = attr.ib()  # int; one of the StateResolutionVersions
    enforce_key_validity = attr.ib()  # bool


class RoomVersions(object):
    V1 = RoomVersion(
        "1",
        RoomDisposition.STABLE,
        EventFormatVersions.V1,
        StateResolutionVersions.V1,
        enforce_key_validity=False,
    )
    V2 = RoomVersion(
        "2",
        RoomDisposition.STABLE,
        EventFormatVersions.V1,
        StateResolutionVersions.V2,
        enforce_key_validity=False,
    )
    V3 = RoomVersion(
        "3",
        RoomDisposition.STABLE,
        EventFormatVersions.V2,
        StateResolutionVersions.V2,
        enforce_key_validity=False,
    )
    V4 = RoomVersion(
        "4",
        RoomDisposition.STABLE,
        EventFormatVersions.V3,
        StateResolutionVersions.V2,
        enforce_key_validity=False,
    )
    V5 = RoomVersion(
        "5",
        RoomDisposition.STABLE,
        EventFormatVersions.V3,
        StateResolutionVersions.V2,
        enforce_key_validity=True,
    )


KNOWN_ROOM_VERSIONS = {
    v.identifier: v
    for v in (
        RoomVersions.V1,
        RoomVersions.V2,
        RoomVersions.V3,
        RoomVersions.V4,
        RoomVersions.V5,
    )
}  # type: dict[str, RoomVersion]
