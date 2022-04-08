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
from typing import TYPE_CHECKING, List, Optional, Union

import attr

from synapse.api.errors import NotFoundError, SynapseError, UnrecognizedRequestError
from synapse.push.baserules import BASE_RULE_IDS
from synapse.types import JsonDict

if TYPE_CHECKING:
    from synapse.server import HomeServer


@attr.s(slots=True, frozen=True, auto_attribs=True)
class RuleSpec:
    scope: str
    template: str
    rule_id: str
    attr: Optional[str]


class PushRulesHandler:
    def __init__(self, hs: "HomeServer"):
        self._notifier = hs.get_notifier()
        self._store = hs.get_datastores().main

    async def set_rule_attr(
        self, user_id: str, spec: RuleSpec, val: Union[bool, JsonDict]
    ) -> None:
        """Set an attribute (enabled or actions) on an existing push rule.

        Args:
            user_id: the user for which to modify the push rule.
            spec: the spec of the push rule to modify.
            val: the value to change the attribute to.
        """
        if spec.attr not in ("enabled", "actions"):
            # for the sake of potential future expansion, shouldn't report
            # 404 in the case of an unknown request so check it corresponds to
            # a known attribute first.
            raise UnrecognizedRequestError()

        namespaced_rule_id = namespaced_rule_id_from_spec(spec)
        rule_id = spec.rule_id
        is_default_rule = rule_id.startswith(".")
        if is_default_rule:
            if namespaced_rule_id not in BASE_RULE_IDS:
                raise NotFoundError("Unknown rule %s" % (namespaced_rule_id,))
        if spec.attr == "enabled":
            if isinstance(val, dict) and "enabled" in val:
                val = val["enabled"]
            if not isinstance(val, bool):
                # Legacy fallback
                # This should *actually* take a dict, but many clients pass
                # bools directly, so let's not break them.
                raise SynapseError(400, "Value for 'enabled' must be boolean")
            await self._store.set_push_rule_enabled(
                user_id, namespaced_rule_id, val, is_default_rule
            )
        elif spec.attr == "actions":
            if not isinstance(val, dict):
                raise SynapseError(400, "Value must be a dict")
            actions = val.get("actions")
            if not isinstance(actions, list):
                raise SynapseError(400, "Value for 'actions' must be dict")
            check_actions(actions)
            rule_id = spec.rule_id
            is_default_rule = rule_id.startswith(".")
            if is_default_rule:
                if namespaced_rule_id not in BASE_RULE_IDS:
                    raise SynapseError(404, "Unknown rule %r" % (namespaced_rule_id,))
            await self._store.set_push_rule_actions(
                user_id, namespaced_rule_id, actions, is_default_rule
            )
        else:
            raise UnrecognizedRequestError()

    def notify_user(self, user_id: str) -> None:
        stream_id = self._store.get_max_push_rules_stream_id()
        self._notifier.on_new_event("push_rules_key", stream_id, users=[user_id])


def check_actions(actions: List[Union[str, JsonDict]]) -> None:
    """Check if the given actions are spec compliant.

    Args:
        actions: the actions to check.

    Raises:
        InvalidRuleException if the rules aren't compliant with the spec.
    """
    if not isinstance(actions, list):
        raise InvalidRuleException("No actions found")

    for a in actions:
        if a in ["notify", "dont_notify", "coalesce"]:
            pass
        elif isinstance(a, dict) and "set_tweak" in a:
            pass
        else:
            raise InvalidRuleException("Unrecognised action")


def namespaced_rule_id_from_spec(spec: RuleSpec) -> str:
    """Generates a scope/kind/rule_id representation of a rule using only its spec."""
    return namespaced_rule_id(spec, spec.rule_id)


def namespaced_rule_id(spec: RuleSpec, rule_id: str) -> str:
    """Generates a scope/kind/rule_id representation of a rule based on another rule's
    spec and a rule ID.
    """
    return "global/%s/%s" % (spec.template, rule_id)


class InvalidRuleException(Exception):
    pass
