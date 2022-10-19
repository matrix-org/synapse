# Copyright 2016 OpenMarket Ltd
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
from typing import Any, Dict, List, Optional

from synapse.push.rulekinds import PRIORITY_CLASS_INVERSE_MAP, PRIORITY_CLASS_MAP
from synapse.synapse_rust.push import FilteredPushRules, PushRule
from synapse.types import UserID


def format_push_rules_for_user(
    user: UserID, ruleslist: FilteredPushRules
) -> Dict[str, Dict[str, list]]:
    """Converts a list of rawrules and a enabled map into nested dictionaries
    to match the Matrix client-server format for push rules"""

    rules: Dict[str, Dict[str, List[Dict[str, Any]]]] = {
        "global": {},
        "device": {},
    }

    rules["global"] = _add_empty_priority_class_arrays(rules["global"])

    for r, enabled in ruleslist.rules():
        template_name = _priority_class_to_template_name(r.priority_class)

        rulearray = rules["global"][template_name]

        template_rule = _rule_to_template(r)
        if not template_rule:
            continue

        rulearray.append(template_rule)

        template_rule["enabled"] = enabled

        if "conditions" not in template_rule:
            # Not all formatted rules have explicit conditions, e.g. "room"
            # rules omit them as they can be derived from the kind and rule ID.
            #
            # If the formatted rule has no conditions then we can skip the
            # formatting of conditions.
            continue

        # Remove internal stuff.
        template_rule["conditions"] = copy.deepcopy(template_rule["conditions"])
        for c in template_rule["conditions"]:
            c.pop("_cache_key", None)

            pattern_type = c.pop("pattern_type", None)
            if pattern_type == "user_id":
                c["pattern"] = user.to_string()
            elif pattern_type == "user_localpart":
                c["pattern"] = user.localpart

            sender_type = c.pop("sender_type", None)
            if sender_type == "user_id":
                c["sender"] = user.to_string()

    return rules


def _add_empty_priority_class_arrays(d: Dict[str, list]) -> Dict[str, list]:
    for pc in PRIORITY_CLASS_MAP.keys():
        d[pc] = []
    return d


def _rule_to_template(rule: PushRule) -> Optional[Dict[str, Any]]:
    templaterule: Dict[str, Any]

    unscoped_rule_id = _rule_id_from_namespaced(rule.rule_id)

    template_name = _priority_class_to_template_name(rule.priority_class)
    if template_name in ["override", "underride"]:
        templaterule = {"conditions": rule.conditions, "actions": rule.actions}
    elif template_name in ["sender", "room"]:
        templaterule = {"actions": rule.actions}
        unscoped_rule_id = rule.conditions[0]["pattern"]
    elif template_name == "content":
        if len(rule.conditions) != 1:
            return None
        thecond = rule.conditions[0]
        if "pattern" not in thecond:
            return None
        templaterule = {"actions": rule.actions}
        templaterule["pattern"] = thecond["pattern"]
    else:
        # This should not be reached unless this function is not kept in sync
        # with PRIORITY_CLASS_INVERSE_MAP.
        raise ValueError("Unexpected template_name: %s" % (template_name,))

    templaterule["rule_id"] = unscoped_rule_id
    templaterule["default"] = rule.default
    return templaterule


def _rule_id_from_namespaced(in_rule_id: str) -> str:
    return in_rule_id.split("/")[-1]


def _priority_class_to_template_name(pc: int) -> str:
    return PRIORITY_CLASS_INVERSE_MAP[pc]
