from typing import Any, Collection, Dict, Mapping, Optional, Sequence, Set, Tuple, Union

from synapse.types import JsonDict

class PushRule:
    rule_id: str
    priority_class: int
    conditions: Sequence[Mapping[str, str]]
    actions: Sequence[Union[Mapping[str, Any], str]]
    default: bool
    default_enabled: bool

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
        msc3786_enabled: bool,
        msc3772_enabled: bool,
    ): ...
    def rules(self) -> Collection[Tuple[PushRule, bool]]: ...

class PushRuleEvaluator:
    def __init__(
        self,
        flattened_keys: Mapping[str, str],
        room_member_count: int,
        sender_power_level: int,
        notification_power_levels: Mapping[str, int],
        relations: Mapping[str, Set[Tuple[str, str]]],
        relation_match_enabled: bool,
    ): ...
    def run(
        self,
        push_rules: FilteredPushRules,
        user_id: Optional[str],
        display_name: Optional[str],
    ) -> Collection[dict]: ...
