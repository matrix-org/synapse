from time import time
from typing import Any, Collection, Dict, List

from synapse.api.constants import EventTypes
from synapse.api.room_versions import RoomVersions
from synapse.config.experimental import ExperimentalConfig
from synapse.events import EventBase, make_event_from_dict
from synapse.push.baserules import FilteredPushRules, PushRules
from synapse.push.push_rule_evaluator import PushRuleEvaluatorForEvent


def compute_push_actions(
    experimental_config: ExperimentalConfig,
    evaluator: PushRuleEvaluatorForEvent,
    event: EventBase,
    rules_by_user: Dict[str, FilteredPushRules],
    profiles: Dict[str, Any],
    count_as_unread: bool,
    uids_with_visibility: Collection[str],
) -> Dict[str, List]:
    actions_by_user = {}

    default_rules = FilteredPushRules(PushRules(), {}, experimental_config)

    matching_default_rule = None
    for rule, _ in default_rules:
        if not rule.default_enabled:
            continue

        matches = evaluator.check_conditions(rule.conditions, "uid", None)
        if matches:
            matching_default_rule = rule
            break

    joining_user = None
    if event.type == EventTypes.Member:
        joining_user = event.state_key

    for uid, rules in rules_by_user.items():
        if event.sender == uid:
            try:
                actions_by_user.pop(uid)
            except KeyError:
                pass
            continue

        if uid not in uids_with_visibility:
            try:
                actions_by_user.pop(uid)
            except KeyError:
                pass
            continue

        display_name = None
        profile = profiles.get(uid)
        if profile:
            display_name = profile.display_name

        if not display_name and joining_user:
            # Handle the case where we are pushing a membership event to
            # that user, as they might not be already joined.
            if joining_user == uid:
                display_name = event.content.get("displayname", None)
                if not isinstance(display_name, str):
                    display_name = None

        if count_as_unread:
            # Add an element for the current user if the event needs to be marked as
            # unread, so that add_push_actions_to_staging iterates over it.
            # If the event shouldn't be marked as unread but should notify the
            # current user, it'll be added to the dict later.
            actions_by_user[uid] = []

        matched_default = False
        if matching_default_rule:
            if not rules.enabled_map.get(matching_default_rule.rule_id, True):
                continue

            matched_default = True

            override = rules.push_rules.overriden_base_rules.get(
                matching_default_rule.rule_id
            )
            if override:
                actions = override.actions
            else:
                actions = matching_default_rule.actions

            actions = [x for x in actions if x != "dont_notify"]

            if actions and "notify" in actions:
                actions_by_user[uid] = matching_default_rule.actions

        for rule, enabled in rules.user_specific_rules():
            if not enabled:
                continue

            if (
                matched_default
                and rule.priority_class < matching_default_rule.priority_class
            ):
                break

            matches = evaluator.check_conditions(rule.conditions, uid, display_name)
            if matches:
                actions = [x for x in rule.actions if x != "dont_notify"]
                if actions and "notify" in actions:
                    # Push rules say we should notify the user of this event
                    actions_by_user[uid] = actions
                else:
                    try:
                        actions_by_user.pop(uid)
                    except KeyError:
                        pass
                break

    return actions_by_user


if __name__ == "__main__":
    event = make_event_from_dict(
        {
            "auth_events": [
                "$Y6V1n3kQq_G2Q2gqma4tXbS0TtZQYne-zk8EGymcErI",
                "$RWzLUHmF5Hc6kr5hJuCY7gcDt3bVXS2JL6oJD7lTEdo",
                "$uIZRw93tT3lXnpMj40J8aPbnDkXeaWtgJWBVrfeQsYs",
            ],
            "prev_events": ["$6lCOe9WyCBREZrvfdShVHO7OgBZ3HA82AN-TsGzsj94"],
            "type": "m.room.message",
            "room_id": "!mWlQLVyRcFtLrKOgEl:localhost:8448",
            "sender": "@user-nn87-main:localhost:8448",
            "content": {
                "org.matrix.msc1767.text": "test",
                "body": "test",
                "msgtype": "m.text",
            },
            "depth": 5006,
            "prev_state": [],
            "origin": "localhost:8448",
            "origin_server_ts": 1660738396696,
            "hashes": {"sha256": "j2X9zgQU6jUqARb9blCdX5UL8SKKJgG1cTxb7uZOiLI"},
            "signatures": {
                "localhost:8448": {
                    "ed25519:a_ERAh": "BsToq2Bf2DqksU5i7vsMN2hxgRBmou+5++IK4+Af8GLt46E9Po1L5Iv1JLxe4eN/zN/jYW03ULGdrzzJkCzaDA"
                }
            },
            "unsigned": {"age_ts": 1660738396696},
        },
        RoomVersions.V10,
    )
    evaluator = PushRuleEvaluatorForEvent(event, 5000, 0, {}, {}, False)

    experimental_config = ExperimentalConfig()
    experimental_config.read_config({})

    rules_by_user = {
        f"@user-{i}:localhost": FilteredPushRules(PushRules(), {}, experimental_config)
        for i in range(5000)
    }

    uids_with_visibility = set(rules_by_user)

    start = time()
    number = 100

    for _ in range(number):
        result = compute_push_actions(
            experimental_config,
            evaluator,
            event,
            rules_by_user,
            {},
            True,
            uids_with_visibility,
        )

    end = time()

    print(f"Average time: {(end - start)*1000/number:.3}ms")
