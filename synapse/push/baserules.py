# Copyright 2015, 2016 OpenMarket Ltd
# Copyright 2017 New Vector Ltd
# Copyright 2019 The Matrix.org Foundation C.I.C.
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

import copy
from typing import Any, Dict, List

from synapse.push.rulekinds import PRIORITY_CLASS_INVERSE_MAP, PRIORITY_CLASS_MAP


def list_with_base_rules(rawrules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Combine the list of rules set by the user with the default push rules

    Args:
        rawrules: The rules the user has modified or set.

    Returns:
        A new list with the rules set by the user combined with the defaults.
    """
    ruleslist = []

    # Grab the base rules that the user has modified.
    # The modified base rules have a priority_class of -1.
    modified_base_rules = {r["rule_id"]: r for r in rawrules if r["priority_class"] < 0}

    # Remove the modified base rules from the list, They'll be added back
    # in the default positions in the list.
    rawrules = [r for r in rawrules if r["priority_class"] >= 0]

    # shove the server default rules for each kind onto the end of each
    current_prio_class = list(PRIORITY_CLASS_INVERSE_MAP)[-1]

    ruleslist.extend(
        make_base_prepend_rules(
            PRIORITY_CLASS_INVERSE_MAP[current_prio_class], modified_base_rules
        )
    )

    for r in rawrules:
        if r["priority_class"] < current_prio_class:
            while r["priority_class"] < current_prio_class:
                ruleslist.extend(
                    make_base_append_rules(
                        PRIORITY_CLASS_INVERSE_MAP[current_prio_class],
                        modified_base_rules,
                    )
                )
                current_prio_class -= 1
                if current_prio_class > 0:
                    ruleslist.extend(
                        make_base_prepend_rules(
                            PRIORITY_CLASS_INVERSE_MAP[current_prio_class],
                            modified_base_rules,
                        )
                    )

        ruleslist.append(r)

    while current_prio_class > 0:
        ruleslist.extend(
            make_base_append_rules(
                PRIORITY_CLASS_INVERSE_MAP[current_prio_class], modified_base_rules
            )
        )
        current_prio_class -= 1
        if current_prio_class > 0:
            ruleslist.extend(
                make_base_prepend_rules(
                    PRIORITY_CLASS_INVERSE_MAP[current_prio_class], modified_base_rules
                )
            )

    return ruleslist


def make_base_append_rules(
    kind: str, modified_base_rules: Dict[str, Dict[str, Any]]
) -> List[Dict[str, Any]]:
    rules = []

    if kind == "override":
        rules = BASE_APPEND_OVERRIDE_RULES
    elif kind == "underride":
        rules = BASE_APPEND_UNDERRIDE_RULES
    elif kind == "content":
        rules = BASE_APPEND_CONTENT_RULES

    # Copy the rules before modifying them
    rules = copy.deepcopy(rules)
    for r in rules:
        # Only modify the actions, keep the conditions the same.
        assert isinstance(r["rule_id"], str)
        modified = modified_base_rules.get(r["rule_id"])
        if modified:
            r["actions"] = modified["actions"]

    return rules


def make_base_prepend_rules(
    kind: str,
    modified_base_rules: Dict[str, Dict[str, Any]],
) -> List[Dict[str, Any]]:
    rules = []

    if kind == "override":
        rules = BASE_PREPEND_OVERRIDE_RULES

    # Copy the rules before modifying them
    rules = copy.deepcopy(rules)
    for r in rules:
        # Only modify the actions, keep the conditions the same.
        assert isinstance(r["rule_id"], str)
        modified = modified_base_rules.get(r["rule_id"])
        if modified:
            r["actions"] = modified["actions"]

    return rules


# We have to annotate these types, otherwise mypy infers them as
# `List[Dict[str, Sequence[Collection[str]]]]`.
BASE_APPEND_CONTENT_RULES: List[Dict[str, Any]] = [
    {
        "rule_id": "global/content/.m.rule.contains_user_name",
        "conditions": [
            {
                "kind": "event_match",
                "key": "content.body",
                # Match the localpart of the requester's MXID.
                "pattern_type": "user_localpart",
            }
        ],
        "actions": [
            "notify",
            {"set_tweak": "sound", "value": "default"},
            {"set_tweak": "highlight"},
        ],
    }
]


BASE_PREPEND_OVERRIDE_RULES: List[Dict[str, Any]] = [
    {
        "rule_id": "global/override/.m.rule.master",
        "enabled": False,
        "conditions": [],
        "actions": ["dont_notify"],
    }
]


BASE_APPEND_OVERRIDE_RULES: List[Dict[str, Any]] = [
    {
        "rule_id": "global/override/.m.rule.suppress_notices",
        "conditions": [
            {
                "kind": "event_match",
                "key": "content.msgtype",
                "pattern": "m.notice",
                "_cache_key": "_suppress_notices",
            }
        ],
        "actions": ["dont_notify"],
    },
    # NB. .m.rule.invite_for_me must be higher prio than .m.rule.member_event
    # otherwise invites will be matched by .m.rule.member_event
    {
        "rule_id": "global/override/.m.rule.invite_for_me",
        "conditions": [
            {
                "kind": "event_match",
                "key": "type",
                "pattern": "m.room.member",
                "_cache_key": "_member",
            },
            {
                "kind": "event_match",
                "key": "content.membership",
                "pattern": "invite",
                "_cache_key": "_invite_member",
            },
            # Match the requester's MXID.
            {"kind": "event_match", "key": "state_key", "pattern_type": "user_id"},
        ],
        "actions": [
            "notify",
            {"set_tweak": "sound", "value": "default"},
            {"set_tweak": "highlight", "value": False},
        ],
    },
    # Will we sometimes want to know about people joining and leaving?
    # Perhaps: if so, this could be expanded upon. Seems the most usual case
    # is that we don't though. We add this override rule so that even if
    # the room rule is set to notify, we don't get notifications about
    # join/leave/avatar/displayname events.
    # See also: https://matrix.org/jira/browse/SYN-607
    {
        "rule_id": "global/override/.m.rule.member_event",
        "conditions": [
            {
                "kind": "event_match",
                "key": "type",
                "pattern": "m.room.member",
                "_cache_key": "_member",
            }
        ],
        "actions": ["dont_notify"],
    },
    # This was changed from underride to override so it's closer in priority
    # to the content rules where the user name highlight rule lives. This
    # way a room rule is lower priority than both but a custom override rule
    # is higher priority than both.
    {
        "rule_id": "global/override/.m.rule.contains_display_name",
        "conditions": [{"kind": "contains_display_name"}],
        "actions": [
            "notify",
            {"set_tweak": "sound", "value": "default"},
            {"set_tweak": "highlight"},
        ],
    },
    {
        "rule_id": "global/override/.m.rule.roomnotif",
        "conditions": [
            {
                "kind": "event_match",
                "key": "content.body",
                "pattern": "@room",
                "_cache_key": "_roomnotif_content",
            },
            {
                "kind": "sender_notification_permission",
                "key": "room",
                "_cache_key": "_roomnotif_pl",
            },
        ],
        "actions": ["notify", {"set_tweak": "highlight", "value": True}],
    },
    {
        "rule_id": "global/override/.m.rule.tombstone",
        "conditions": [
            {
                "kind": "event_match",
                "key": "type",
                "pattern": "m.room.tombstone",
                "_cache_key": "_tombstone",
            },
            {
                "kind": "event_match",
                "key": "state_key",
                "pattern": "",
                "_cache_key": "_tombstone_statekey",
            },
        ],
        "actions": ["notify", {"set_tweak": "highlight", "value": True}],
    },
    {
        "rule_id": "global/override/.m.rule.reaction",
        "conditions": [
            {
                "kind": "event_match",
                "key": "type",
                "pattern": "m.reaction",
                "_cache_key": "_reaction",
            }
        ],
        "actions": ["dont_notify"],
    },
    # XXX: This is an experimental rule that is only enabled if msc3786_enabled
    # is enabled, if it is not the rule gets filtered out in _load_rules() in
    # PushRulesWorkerStore
    {
        "rule_id": "global/override/.org.matrix.msc3786.rule.room.server_acl",
        "conditions": [
            {
                "kind": "event_match",
                "key": "type",
                "pattern": "m.room.server_acl",
                "_cache_key": "_room_server_acl",
            },
            {
                "kind": "event_match",
                "key": "state_key",
                "pattern": "",
                "_cache_key": "_room_server_acl_state_key",
            },
        ],
        "actions": [],
    },
]


BASE_APPEND_UNDERRIDE_RULES: List[Dict[str, Any]] = [
    {
        "rule_id": "global/underride/.m.rule.call",
        "conditions": [
            {
                "kind": "event_match",
                "key": "type",
                "pattern": "m.call.invite",
                "_cache_key": "_call",
            }
        ],
        "actions": [
            "notify",
            {"set_tweak": "sound", "value": "ring"},
            {"set_tweak": "highlight", "value": False},
        ],
    },
    # XXX: once m.direct is standardised everywhere, we should use it to detect
    # a DM from the user's perspective rather than this heuristic.
    {
        "rule_id": "global/underride/.m.rule.room_one_to_one",
        "conditions": [
            {"kind": "room_member_count", "is": "2", "_cache_key": "member_count"},
            {
                "kind": "event_match",
                "key": "type",
                "pattern": "m.room.message",
                "_cache_key": "_message",
            },
        ],
        "actions": [
            "notify",
            {"set_tweak": "sound", "value": "default"},
            {"set_tweak": "highlight", "value": False},
        ],
    },
    # XXX: this is going to fire for events which aren't m.room.messages
    # but are encrypted (e.g. m.call.*)...
    {
        "rule_id": "global/underride/.m.rule.encrypted_room_one_to_one",
        "conditions": [
            {"kind": "room_member_count", "is": "2", "_cache_key": "member_count"},
            {
                "kind": "event_match",
                "key": "type",
                "pattern": "m.room.encrypted",
                "_cache_key": "_encrypted",
            },
        ],
        "actions": [
            "notify",
            {"set_tweak": "sound", "value": "default"},
            {"set_tweak": "highlight", "value": False},
        ],
    },
    {
        "rule_id": "global/underride/.org.matrix.msc3772.thread_reply",
        "conditions": [
            {
                "kind": "org.matrix.msc3772.relation_match",
                "rel_type": "m.thread",
                # Match the requester's MXID.
                "sender_type": "user_id",
            }
        ],
        "actions": ["notify", {"set_tweak": "highlight", "value": False}],
    },
    {
        "rule_id": "global/underride/.m.rule.message",
        "conditions": [
            {
                "kind": "event_match",
                "key": "type",
                "pattern": "m.room.message",
                "_cache_key": "_message",
            }
        ],
        "actions": ["notify", {"set_tweak": "highlight", "value": False}],
    },
    # XXX: this is going to fire for events which aren't m.room.messages
    # but are encrypted (e.g. m.call.*)...
    {
        "rule_id": "global/underride/.m.rule.encrypted",
        "conditions": [
            {
                "kind": "event_match",
                "key": "type",
                "pattern": "m.room.encrypted",
                "_cache_key": "_encrypted",
            }
        ],
        "actions": ["notify", {"set_tweak": "highlight", "value": False}],
    },
    {
        "rule_id": "global/underride/.im.vector.jitsi",
        "conditions": [
            {
                "kind": "event_match",
                "key": "type",
                "pattern": "im.vector.modular.widgets",
                "_cache_key": "_type_modular_widgets",
            },
            {
                "kind": "event_match",
                "key": "content.type",
                "pattern": "jitsi",
                "_cache_key": "_content_type_jitsi",
            },
            {
                "kind": "event_match",
                "key": "state_key",
                "pattern": "*",
                "_cache_key": "_is_state_event",
            },
        ],
        "actions": ["notify", {"set_tweak": "highlight", "value": False}],
    },
]


BASE_RULE_IDS = set()

for r in BASE_APPEND_CONTENT_RULES:
    r["priority_class"] = PRIORITY_CLASS_MAP["content"]
    r["default"] = True
    BASE_RULE_IDS.add(r["rule_id"])

for r in BASE_PREPEND_OVERRIDE_RULES:
    r["priority_class"] = PRIORITY_CLASS_MAP["override"]
    r["default"] = True
    BASE_RULE_IDS.add(r["rule_id"])

for r in BASE_APPEND_OVERRIDE_RULES:
    r["priority_class"] = PRIORITY_CLASS_MAP["override"]
    r["default"] = True
    BASE_RULE_IDS.add(r["rule_id"])

for r in BASE_APPEND_UNDERRIDE_RULES:
    r["priority_class"] = PRIORITY_CLASS_MAP["underride"]
    r["default"] = True
    BASE_RULE_IDS.add(r["rule_id"])
