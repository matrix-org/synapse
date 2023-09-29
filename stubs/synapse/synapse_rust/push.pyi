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

from typing import Any, Collection, Dict, Mapping, Optional, Sequence, Tuple, Union

from synapse.types import JsonDict, JsonValue

class PushRule:
    @property
    def rule_id(self) -> str: ...
    @property
    def priority_class(self) -> int: ...
    @property
    def conditions(self) -> Sequence[Mapping[str, str]]: ...
    @property
    def actions(self) -> Sequence[Union[Mapping[str, Any], str]]: ...
    @property
    def default(self) -> bool: ...
    @property
    def default_enabled(self) -> bool: ...
    @staticmethod
    def from_db(
        rule_id: str, priority_class: int, conditions: str, actions: str
    ) -> "PushRule": ...

class PushRules:
    def __init__(self, rules: Collection[PushRule]): ...
    def rules(self) -> Collection[PushRule]: ...

class FilteredPushRules:
    def __init__(
        self,
        push_rules: PushRules,
        enabled_map: Dict[str, bool],
        msc1767_enabled: bool,
        msc3381_polls_enabled: bool,
        msc3664_enabled: bool,
        msc4028_push_encrypted_events: bool,
    ): ...
    def rules(self) -> Collection[Tuple[PushRule, bool]]: ...

def get_base_rule_ids() -> Collection[str]: ...

class PushRuleEvaluator:
    def __init__(
        self,
        flattened_keys: Mapping[str, JsonValue],
        has_mentions: bool,
        room_member_count: int,
        sender_power_level: Optional[int],
        notification_power_levels: Mapping[str, int],
        related_events_flattened: Mapping[str, Mapping[str, JsonValue]],
        related_event_match_enabled: bool,
        room_version_feature_flags: Tuple[str, ...],
        msc3931_enabled: bool,
    ): ...
    def run(
        self,
        push_rules: FilteredPushRules,
        user_id: Optional[str],
        display_name: Optional[str],
    ) -> Collection[Union[Mapping, str]]: ...
    def matches(
        self, condition: JsonDict, user_id: Optional[str], display_name: Optional[str]
    ) -> bool: ...
