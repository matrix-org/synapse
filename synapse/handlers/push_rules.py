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

from synapse.api.errors import SynapseError, UnrecognizedRequestError
from synapse.storage.push_rule import RuleNotFoundException
from synapse.synapse_rust.push import get_base_rule_ids
from synapse.types import JsonDict

if TYPE_CHECKING:
    from synapse.server import HomeServer


BASE_RULE_IDS = get_base_rule_ids()


@attr.s(slots=True, frozen=True, auto_attribs=True)
class RuleSpec:
    scope: str
    template: str
    rule_id: str
    attr: Optional[str]


class PushRulesHandler:
    """A class to handle changes in push rules for users."""

    def __init__(self, hs: "HomeServer"):
        self._notifier = hs.get_notifier()
        self._main_store = hs.get_datastores().main

    async def set_rule_attr(
        self, user_id: str, spec: RuleSpec, val: Union[bool, JsonDict]
    ) -> None:
        """Set an attribute (enabled or actions) on an existing push rule.

        Notifies listeners (e.g. sync handler) of the change.

        Args:
            user_id: the user for which to modify the push rule.
            spec: the spec of the push rule to modify.
            val: the value to change the attribute to.

        Raises:
            RuleNotFoundException if the rule being modified doesn't exist.
            SynapseError(400) if the value is malformed.
            UnrecognizedRequestError if the attribute to change is unknown.
            InvalidRuleException if we're trying to change the actions on a rule but
                the provided actions aren't compliant with the spec.
        """
        if spec.attr not in ("enabled", "actions"):
            # for the sake of potential future expansion, shouldn't report
            # 404 in the case of an unknown request so check it corresponds to
            # a known attribute first.
            raise UnrecognizedRequestError()

        namespaced_rule_id = f"global/{spec.template}/{spec.rule_id}"
        rule_id = spec.rule_id
        is_default_rule = rule_id.startswith(".")
        if is_default_rule:
            if namespaced_rule_id not in BASE_RULE_IDS:
                raise RuleNotFoundException("Unknown rule %r" % (namespaced_rule_id,))
        if spec.attr == "enabled":
            if isinstance(val, dict) and "enabled" in val:
                val = val["enabled"]
            if not isinstance(val, bool):
                # Legacy fallback
                # This should *actually* take a dict, but many clients pass
                # bools directly, so let's not break them.
                raise SynapseError(400, "Value for 'enabled' must be boolean")
            await self._main_store.set_push_rule_enabled(
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
                    raise RuleNotFoundException(
                        "Unknown rule %r" % (namespaced_rule_id,)
                    )
            await self._main_store.set_push_rule_actions(
                user_id, namespaced_rule_id, actions, is_default_rule
            )
        else:
            raise UnrecognizedRequestError()

        self.notify_user(user_id)

    def notify_user(self, user_id: str) -> None:
        """Notify listeners about a push rule change.

        Args:
            user_id: the user ID the change is for.
        """
        stream_id = self._main_store.get_max_push_rules_stream_id()
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
            raise InvalidRuleException("Unrecognised action %s" % a)


class InvalidRuleException(Exception):
    pass
