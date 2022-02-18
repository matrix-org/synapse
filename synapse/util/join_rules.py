# Copyright 2021-2022 The Matrix.org Foundation C.I.C.
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

from synapse.api.constants import JoinRules
from synapse.api.room_versions import RoomVersion
from synapse.events import EventBase

logger = logging.getLogger(__name__)


def is_join_rule(
    room_version: RoomVersion, event: EventBase, expected_rule: JoinRules
) -> bool:
    """Returns whether the join rule event matches the expected join rule.

    Args:
        room_version: The RoomVersion the event is in
        event: The join rules event
        expected_rule: The anticipated rule

    Returns:
        bool: True if the join rule is as expected.
    """
    if not event:
        return expected_rule == JoinRules.INVITE

    if room_version.msc3613_simplified_join_rules:
        arr = event.content.get("join_rules", [])
        if arr and isinstance(arr, list):
            return expected_rule in list(r.get("join_rule", None) for r in arr)

    return event.content.get("join_rule", None) == expected_rule


def get_all_allow_lists(room_version: RoomVersion, event: EventBase) -> list:
    """Returns the combination of all 'allow' lists in the join rules.

    Args:
        room_version: The RoomVersion the event is in
        event: The join rules event

    Returns:
        list: The allow lists from the event, merged
    """
    allow_list = []
    is_using_msc3613 = False
    if room_version.msc3613_simplified_join_rules:
        is_using_msc3613 = True
        rules = event.content.get("join_rules", [])
        if rules and isinstance(rules, list):
            for rule in rules:
                if rule.get("join_rule", None) == JoinRules.RESTRICTED:
                    secondary = rule.get("allow", [])
                    if secondary and isinstance(secondary, list):
                        allow_list.extend(secondary)

    # Only look at the top level `allow` list if the event doesn't specify
    # multiple join rules.
    is_restricted = event.get("join_rule", None) == JoinRules.RESTRICTED
    if not is_using_msc3613 and is_restricted:
        allow_list = event.content.get("allow", [])
        if not allow_list or not isinstance(allow_list, list):
            allow_list = []

    allow_list = allow_list[:]  # clone to prevent mutation
    return allow_list
