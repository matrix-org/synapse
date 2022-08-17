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

"""
Push rules is the system used to determine which events trigger a push (and a
bump in notification counts).

This consists of a list of "push rules" for each user, where a push rule is a
pair of "conditions" and "actions". When a user receives an event Synapse
iterates over the list of push rules until it finds one where all the conditions
match the event, at which point "actions" describe the outcome (e.g. notify,
highlight, etc).

Push rules are split up into 5 different "kinds" (aka "priority classes"), which
are run in order:
    1. Override — highest priority rules, e.g. always ignore notices
    2. Content — content specific rules, e.g. @ notifications
    3. Room — per room rules, e.g. enable/disable notifications for all messages
       in a room
    4. Sender — per sender rules, e.g. never notify for messages from a given
       user
    5. Underride — the lowest priority "default" rules, e.g. notify for every
       message.

The set of "base rules" are the list of rules that every user has by default. A
user can modify their copy of the push rules in one of three ways:

    1. Adding a new push rule of a certain kind
    2. Changing the actions of a base rule
    3. Enabling/disabling a base rule.

The base rules are split into whether they come before or after a particular
kind, so the order of push rule evaluation would be: base rules for before
"override" kind, user defined "override" rules, base rules after "override"
kind, etc, etc.
"""

import itertools
import logging
from typing import Dict, Iterator, List, Mapping, Sequence, Tuple, Union

import attr

from synapse.config.experimental import ExperimentalConfig
from synapse.push.rulekinds import PRIORITY_CLASS_MAP

logger = logging.getLogger(__name__)


@attr.s(auto_attribs=True, slots=True, frozen=True)
class PushRule:
    """A push rule

    Attributes:
        rule_id: a unique ID for this rule
        priority_class: what "kind" of push rule this is (see
            `PRIORITY_CLASS_MAP` for mapping between int and kind)
        conditions: the sequence of conditions that all need to match
        actions: the actions to apply if all conditions are met
        default: is this a base rule?
        default_enabled: is this enabled by default?
    """

    rule_id: str
    priority_class: int
    conditions: Sequence[Mapping[str, str]]
    actions: Sequence[Union[str, Mapping]]
    default: bool = False
    default_enabled: bool = True


@attr.s(auto_attribs=True, slots=True, frozen=True, weakref_slot=False)
class PushRules:
    """A collection of push rules for an account.

    Can be iterated over, producing push rules in priority order.
    """

    # A mapping from rule ID to push rule that overrides a base rule. These will
    # be returned instead of the base rule.
    overriden_base_rules: Dict[str, PushRule] = attr.Factory(dict)

    # The following stores the custom push rules at each priority class.
    #
    # We keep these separate (rather than combining into one big list) to avoid
    # copying the base rules around all the time.
    override: List[PushRule] = attr.Factory(list)
    content: List[PushRule] = attr.Factory(list)
    room: List[PushRule] = attr.Factory(list)
    sender: List[PushRule] = attr.Factory(list)
    underride: List[PushRule] = attr.Factory(list)

    def __iter__(self) -> Iterator[PushRule]:
        # When iterating over the push rules we need to return the base rules
        # interspersed at the correct spots.
        for rule in itertools.chain(
            BASE_PREPEND_OVERRIDE_RULES,
            self.override,
            BASE_APPEND_OVERRIDE_RULES,
            self.content,
            BASE_APPEND_CONTENT_RULES,
            self.room,
            self.sender,
            self.underride,
            BASE_APPEND_UNDERRIDE_RULES,
        ):
            # Check if a base rule has been overriden by a custom rule. If so
            # return that instead.
            override_rule = self.overriden_base_rules.get(rule.rule_id)
            if override_rule:
                yield override_rule
            else:
                yield rule

    def __len__(self) -> int:
        # The length is mostly used by caches to get a sense of "size" / amount
        # of memory this object is using, so we only count the number of custom
        # rules.
        return (
            len(self.overriden_base_rules)
            + len(self.override)
            + len(self.content)
            + len(self.room)
            + len(self.sender)
            + len(self.underride)
        )


@attr.s(auto_attribs=True, slots=True, frozen=True, weakref_slot=False)
class FilteredPushRules:
    """A wrapper around `PushRules` that filters out disabled experimental push
    rules, and includes the "enabled" state for each rule when iterated over.
    """

    push_rules: PushRules
    enabled_map: Dict[str, bool]
    experimental_config: ExperimentalConfig

    def __iter__(self) -> Iterator[Tuple[PushRule, bool]]:
        for rule in self.push_rules:
            if not _is_experimental_rule_enabled(
                rule.rule_id, self.experimental_config
            ):
                continue

            enabled = self.enabled_map.get(rule.rule_id, rule.default_enabled)

            yield rule, enabled

    def __len__(self) -> int:
        return len(self.push_rules)


DEFAULT_EMPTY_PUSH_RULES = PushRules()


def compile_push_rules(rawrules: List[PushRule]) -> PushRules:
    """Given a set of custom push rules return a `PushRules` instance (which
    includes the base rules).
    """

    if not rawrules:
        # Fast path to avoid allocating empty lists when there are no custom
        # rules for the user.
        return DEFAULT_EMPTY_PUSH_RULES

    rules = PushRules()

    for rule in rawrules:
        # We need to decide which bucket each custom push rule goes into.

        # If it has the same ID as a base rule then it overrides that...
        overriden_base_rule = BASE_RULES_BY_ID.get(rule.rule_id)
        if overriden_base_rule:
            rules.overriden_base_rules[rule.rule_id] = attr.evolve(
                overriden_base_rule, actions=rule.actions
            )
            continue

        # ... otherwise it gets added to the appropriate priority class bucket
        collection: List[PushRule]
        if rule.priority_class == 5:
            collection = rules.override
        elif rule.priority_class == 4:
            collection = rules.content
        elif rule.priority_class == 3:
            collection = rules.room
        elif rule.priority_class == 2:
            collection = rules.sender
        elif rule.priority_class == 1:
            collection = rules.underride
        elif rule.priority_class <= 0:
            logger.info(
                "Got rule with priority class less than zero, but doesn't override a base rule: %s",
                rule,
            )
            continue
        else:
            # We log and continue here so as not to break event sending
            logger.error("Unknown priority class: %", rule.priority_class)
            continue

        collection.append(rule)

    return rules


def _is_experimental_rule_enabled(
    rule_id: str, experimental_config: ExperimentalConfig
) -> bool:
    """Used by `FilteredPushRules` to filter out experimental rules when they
    have not been enabled.
    """
    if (
        rule_id == "global/override/.org.matrix.msc3786.rule.room.server_acl"
        and not experimental_config.msc3786_enabled
    ):
        return False
    if (
        rule_id == "global/underride/.org.matrix.msc3772.thread_reply"
        and not experimental_config.msc3772_enabled
    ):
        return False
    return True


BASE_APPEND_CONTENT_RULES = [
    PushRule(
        default=True,
        priority_class=PRIORITY_CLASS_MAP["content"],
        rule_id="global/content/.m.rule.contains_user_name",
        conditions=[
            {
                "kind": "event_match",
                "key": "content.body",
                # Match the localpart of the requester's MXID.
                "pattern_type": "user_localpart",
            }
        ],
        actions=[
            "notify",
            {"set_tweak": "sound", "value": "default"},
            {"set_tweak": "highlight"},
        ],
    )
]


BASE_PREPEND_OVERRIDE_RULES = [
    PushRule(
        default=True,
        priority_class=PRIORITY_CLASS_MAP["override"],
        rule_id="global/override/.m.rule.master",
        default_enabled=False,
        conditions=[],
        actions=["dont_notify"],
    )
]


BASE_APPEND_OVERRIDE_RULES = [
    PushRule(
        default=True,
        priority_class=PRIORITY_CLASS_MAP["override"],
        rule_id="global/override/.m.rule.suppress_notices",
        conditions=[
            {
                "kind": "event_match",
                "key": "content.msgtype",
                "pattern": "m.notice",
                "_cache_key": "_suppress_notices",
            }
        ],
        actions=["dont_notify"],
    ),
    # NB. .m.rule.invite_for_me must be higher prio than .m.rule.member_event
    # otherwise invites will be matched by .m.rule.member_event
    PushRule(
        default=True,
        priority_class=PRIORITY_CLASS_MAP["override"],
        rule_id="global/override/.m.rule.invite_for_me",
        conditions=[
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
        actions=[
            "notify",
            {"set_tweak": "sound", "value": "default"},
            {"set_tweak": "highlight", "value": False},
        ],
    ),
    # Will we sometimes want to know about people joining and leaving?
    # Perhaps: if so, this could be expanded upon. Seems the most usual case
    # is that we don't though. We add this override rule so that even if
    # the room rule is set to notify, we don't get notifications about
    # join/leave/avatar/displayname events.
    # See also: https://matrix.org/jira/browse/SYN-607
    PushRule(
        default=True,
        priority_class=PRIORITY_CLASS_MAP["override"],
        rule_id="global/override/.m.rule.member_event",
        conditions=[
            {
                "kind": "event_match",
                "key": "type",
                "pattern": "m.room.member",
                "_cache_key": "_member",
            }
        ],
        actions=["dont_notify"],
    ),
    # This was changed from underride to override so it's closer in priority
    # to the content rules where the user name highlight rule lives. This
    # way a room rule is lower priority than both but a custom override rule
    # is higher priority than both.
    PushRule(
        default=True,
        priority_class=PRIORITY_CLASS_MAP["override"],
        rule_id="global/override/.m.rule.contains_display_name",
        conditions=[{"kind": "contains_display_name"}],
        actions=[
            "notify",
            {"set_tweak": "sound", "value": "default"},
            {"set_tweak": "highlight"},
        ],
    ),
    PushRule(
        default=True,
        priority_class=PRIORITY_CLASS_MAP["override"],
        rule_id="global/override/.m.rule.roomnotif",
        conditions=[
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
        actions=["notify", {"set_tweak": "highlight", "value": True}],
    ),
    PushRule(
        default=True,
        priority_class=PRIORITY_CLASS_MAP["override"],
        rule_id="global/override/.m.rule.tombstone",
        conditions=[
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
        actions=["notify", {"set_tweak": "highlight", "value": True}],
    ),
    PushRule(
        default=True,
        priority_class=PRIORITY_CLASS_MAP["override"],
        rule_id="global/override/.m.rule.reaction",
        conditions=[
            {
                "kind": "event_match",
                "key": "type",
                "pattern": "m.reaction",
                "_cache_key": "_reaction",
            }
        ],
        actions=["dont_notify"],
    ),
    # XXX: This is an experimental rule that is only enabled if msc3786_enabled
    # is enabled, if it is not the rule gets filtered out in _load_rules() in
    # PushRulesWorkerStore
    PushRule(
        default=True,
        priority_class=PRIORITY_CLASS_MAP["override"],
        rule_id="global/override/.org.matrix.msc3786.rule.room.server_acl",
        conditions=[
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
        actions=[],
    ),
]


BASE_APPEND_UNDERRIDE_RULES = [
    PushRule(
        default=True,
        priority_class=PRIORITY_CLASS_MAP["underride"],
        rule_id="global/underride/.m.rule.call",
        conditions=[
            {
                "kind": "event_match",
                "key": "type",
                "pattern": "m.call.invite",
                "_cache_key": "_call",
            }
        ],
        actions=[
            "notify",
            {"set_tweak": "sound", "value": "ring"},
            {"set_tweak": "highlight", "value": False},
        ],
    ),
    # XXX: once m.direct is standardised everywhere, we should use it to detect
    # a DM from the user's perspective rather than this heuristic.
    PushRule(
        default=True,
        priority_class=PRIORITY_CLASS_MAP["underride"],
        rule_id="global/underride/.m.rule.room_one_to_one",
        conditions=[
            {"kind": "room_member_count", "is": "2", "_cache_key": "member_count"},
            {
                "kind": "event_match",
                "key": "type",
                "pattern": "m.room.message",
                "_cache_key": "_message",
            },
        ],
        actions=[
            "notify",
            {"set_tweak": "sound", "value": "default"},
            {"set_tweak": "highlight", "value": False},
        ],
    ),
    # XXX: this is going to fire for events which aren't m.room.messages
    # but are encrypted (e.g. m.call.*)...
    PushRule(
        default=True,
        priority_class=PRIORITY_CLASS_MAP["underride"],
        rule_id="global/underride/.m.rule.encrypted_room_one_to_one",
        conditions=[
            {"kind": "room_member_count", "is": "2", "_cache_key": "member_count"},
            {
                "kind": "event_match",
                "key": "type",
                "pattern": "m.room.encrypted",
                "_cache_key": "_encrypted",
            },
        ],
        actions=[
            "notify",
            {"set_tweak": "sound", "value": "default"},
            {"set_tweak": "highlight", "value": False},
        ],
    ),
    PushRule(
        default=True,
        priority_class=PRIORITY_CLASS_MAP["underride"],
        rule_id="global/underride/.org.matrix.msc3772.thread_reply",
        conditions=[
            {
                "kind": "org.matrix.msc3772.relation_match",
                "rel_type": "m.thread",
                # Match the requester's MXID.
                "sender_type": "user_id",
            }
        ],
        actions=["notify", {"set_tweak": "highlight", "value": False}],
    ),
    PushRule(
        default=True,
        priority_class=PRIORITY_CLASS_MAP["underride"],
        rule_id="global/underride/.m.rule.message",
        conditions=[
            {
                "kind": "event_match",
                "key": "type",
                "pattern": "m.room.message",
                "_cache_key": "_message",
            }
        ],
        actions=["notify", {"set_tweak": "highlight", "value": False}],
    ),
    # XXX: this is going to fire for events which aren't m.room.messages
    # but are encrypted (e.g. m.call.*)...
    PushRule(
        default=True,
        priority_class=PRIORITY_CLASS_MAP["underride"],
        rule_id="global/underride/.m.rule.encrypted",
        conditions=[
            {
                "kind": "event_match",
                "key": "type",
                "pattern": "m.room.encrypted",
                "_cache_key": "_encrypted",
            }
        ],
        actions=["notify", {"set_tweak": "highlight", "value": False}],
    ),
    PushRule(
        default=True,
        priority_class=PRIORITY_CLASS_MAP["underride"],
        rule_id="global/underride/.im.vector.jitsi",
        conditions=[
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
        actions=["notify", {"set_tweak": "highlight", "value": False}],
    ),
]


BASE_RULE_IDS = set()

BASE_RULES_BY_ID: Dict[str, PushRule] = {}

for r in BASE_APPEND_CONTENT_RULES:
    BASE_RULE_IDS.add(r.rule_id)
    BASE_RULES_BY_ID[r.rule_id] = r

for r in BASE_PREPEND_OVERRIDE_RULES:
    BASE_RULE_IDS.add(r.rule_id)
    BASE_RULES_BY_ID[r.rule_id] = r

for r in BASE_APPEND_OVERRIDE_RULES:
    BASE_RULE_IDS.add(r.rule_id)
    BASE_RULES_BY_ID[r.rule_id] = r

for r in BASE_APPEND_UNDERRIDE_RULES:
    BASE_RULE_IDS.add(r.rule_id)
    BASE_RULES_BY_ID[r.rule_id] = r
