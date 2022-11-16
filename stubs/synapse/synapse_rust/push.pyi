from typing import Any, Collection, Dict, Mapping, Optional, Sequence, Set, Tuple, Union

from synapse.types import JsonDict

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
        self, push_rules: PushRules, enabled_map: Dict[str, bool], msc3664_enabled: bool
    ): ...
    def rules(self) -> Collection[Tuple[PushRule, bool]]: ...

def get_base_rule_ids() -> Collection[str]: ...

class PushRuleEvaluator:
    def __init__(
        self,
        flattened_keys: Mapping[str, str],
        room_member_count: int,
        sender_power_level: Optional[int],
        notification_power_levels: Mapping[str, int],
        related_events_flattened: Mapping[str, Mapping[str, str]],
        related_event_match_enabled: bool,
    ): ...
    def run(
        self,
        push_rules: FilteredPushRules,
        user_id: Optional[str],
        display_name: Optional[str],
    ) -> Collection[dict]: ...
