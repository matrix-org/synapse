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

from typing import Dict

import attr


class EventFormatVersions:
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


class StateResolutionVersions:
    """Enum to identify the state resolution algorithms"""

    V1 = 1  # room v1 state res
    V2 = 2  # MSC1442 state res: room v2 and later


class RoomDisposition:
    STABLE = "stable"
    UNSTABLE = "unstable"


@attr.s(slots=True, frozen=True)
class RoomVersion:
    """An object which describes the unique attributes of a room version."""

    identifier = attr.ib(type=str)  # the identifier for this version
    disposition = attr.ib(type=str)  # one of the RoomDispositions
    event_format = attr.ib(type=int)  # one of the EventFormatVersions
    state_res = attr.ib(type=int)  # one of the StateResolutionVersions
    enforce_key_validity = attr.ib(type=bool)

    # Before MSC2261/MSC2432, m.room.aliases had special auth rules and redaction rules
    special_case_aliases_auth = attr.ib(type=bool)
    # Strictly enforce canonicaljson, do not allow:
    # * Integers outside the range of [-2 ^ 53 + 1, 2 ^ 53 - 1]
    # * Floats
    # * NaN, Infinity, -Infinity
    strict_canonicaljson = attr.ib(type=bool)
    # MSC2209: Check 'notifications' key while verifying
    # m.room.power_levels auth rules.
    limit_notifications_power_levels = attr.ib(type=bool)
    # MSC2174/MSC2176: Apply updated redaction rules algorithm.
    msc2176_redaction_rules = attr.ib(type=bool)
    # MSC3083: Support the 'restricted' join_rule.
    msc3083_join_rules = attr.ib(type=bool)


class RoomVersions:
    V1 = RoomVersion(
        "1",
        RoomDisposition.STABLE,
        EventFormatVersions.V1,
        StateResolutionVersions.V1,
        enforce_key_validity=False,
        special_case_aliases_auth=True,
        strict_canonicaljson=False,
        limit_notifications_power_levels=False,
        msc2176_redaction_rules=False,
        msc3083_join_rules=False,
    )
    V2 = RoomVersion(
        "2",
        RoomDisposition.STABLE,
        EventFormatVersions.V1,
        StateResolutionVersions.V2,
        enforce_key_validity=False,
        special_case_aliases_auth=True,
        strict_canonicaljson=False,
        limit_notifications_power_levels=False,
        msc2176_redaction_rules=False,
        msc3083_join_rules=False,
    )
    V3 = RoomVersion(
        "3",
        RoomDisposition.STABLE,
        EventFormatVersions.V2,
        StateResolutionVersions.V2,
        enforce_key_validity=False,
        special_case_aliases_auth=True,
        strict_canonicaljson=False,
        limit_notifications_power_levels=False,
        msc2176_redaction_rules=False,
        msc3083_join_rules=False,
    )
    V4 = RoomVersion(
        "4",
        RoomDisposition.STABLE,
        EventFormatVersions.V3,
        StateResolutionVersions.V2,
        enforce_key_validity=False,
        special_case_aliases_auth=True,
        strict_canonicaljson=False,
        limit_notifications_power_levels=False,
        msc2176_redaction_rules=False,
        msc3083_join_rules=False,
    )
    V5 = RoomVersion(
        "5",
        RoomDisposition.STABLE,
        EventFormatVersions.V3,
        StateResolutionVersions.V2,
        enforce_key_validity=True,
        special_case_aliases_auth=True,
        strict_canonicaljson=False,
        limit_notifications_power_levels=False,
        msc2176_redaction_rules=False,
        msc3083_join_rules=False,
    )
    V6 = RoomVersion(
        "6",
        RoomDisposition.STABLE,
        EventFormatVersions.V3,
        StateResolutionVersions.V2,
        enforce_key_validity=True,
        special_case_aliases_auth=False,
        strict_canonicaljson=True,
        limit_notifications_power_levels=True,
        msc2176_redaction_rules=False,
        msc3083_join_rules=False,
    )
    MSC2176 = RoomVersion(
        "org.matrix.msc2176",
        RoomDisposition.UNSTABLE,
        EventFormatVersions.V3,
        StateResolutionVersions.V2,
        enforce_key_validity=True,
        special_case_aliases_auth=False,
        strict_canonicaljson=True,
        limit_notifications_power_levels=True,
        msc2176_redaction_rules=True,
        msc3083_join_rules=False,
    )
    MSC3083 = RoomVersion(
        "org.matrix.msc3083",
        RoomDisposition.UNSTABLE,
        EventFormatVersions.V3,
        StateResolutionVersions.V2,
        enforce_key_validity=True,
        special_case_aliases_auth=False,
        strict_canonicaljson=True,
        limit_notifications_power_levels=True,
        msc2176_redaction_rules=False,
        msc3083_join_rules=True,
    )


KNOWN_ROOM_VERSIONS = {
    v.identifier: v
    for v in (
        RoomVersions.V1,
        RoomVersions.V2,
        RoomVersions.V3,
        RoomVersions.V4,
        RoomVersions.V5,
        RoomVersions.V6,
        RoomVersions.MSC2176,
    )
    # Note that we do not include MSC3083 here unless it is enabled in the config.
}  # type: Dict[str, RoomVersion]
