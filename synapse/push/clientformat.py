# -*- coding: utf-8 -*-
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

from synapse.push.rulekinds import (
    PRIORITY_CLASS_MAP, PRIORITY_CLASS_INVERSE_MAP
)

import copy


def format_push_rules_for_user(user, ruleslist):
    """Converts a list of rawrules and a enabled map into nested dictionaries
    to match the Matrix client-server format for push rules"""

    # We're going to be mutating this a lot, so do a deep copy
    ruleslist = copy.deepcopy(ruleslist)

    rules = {'global': {}, 'device': {}}

    rules['global'] = _add_empty_priority_class_arrays(rules['global'])

    for r in ruleslist:
        rulearray = None

        template_name = _priority_class_to_template_name(r['priority_class'])

        # Remove internal stuff.
        for c in r["conditions"]:
            c.pop("_id", None)

            pattern_type = c.pop("pattern_type", None)
            if pattern_type == "user_id":
                c["pattern"] = user.to_string()
            elif pattern_type == "user_localpart":
                c["pattern"] = user.localpart

        rulearray = rules['global'][template_name]

        template_rule = _rule_to_template(r)
        if template_rule:
            if 'enabled' in r:
                template_rule['enabled'] = r['enabled']
            else:
                template_rule['enabled'] = True
            rulearray.append(template_rule)

    return rules


def _add_empty_priority_class_arrays(d):
    for pc in PRIORITY_CLASS_MAP.keys():
        d[pc] = []
    return d


def _rule_to_template(rule):
    unscoped_rule_id = None
    if 'rule_id' in rule:
        unscoped_rule_id = _rule_id_from_namespaced(rule['rule_id'])

    template_name = _priority_class_to_template_name(rule['priority_class'])
    if template_name in ['override', 'underride']:
        templaterule = {k: rule[k] for k in ["conditions", "actions"]}
    elif template_name in ["sender", "room"]:
        templaterule = {'actions': rule['actions']}
        unscoped_rule_id = rule['conditions'][0]['pattern']
    elif template_name == 'content':
        if len(rule["conditions"]) != 1:
            return None
        thecond = rule["conditions"][0]
        if "pattern" not in thecond:
            return None
        templaterule = {'actions': rule['actions']}
        templaterule["pattern"] = thecond["pattern"]

    if unscoped_rule_id:
            templaterule['rule_id'] = unscoped_rule_id
    if 'default' in rule:
        templaterule['default'] = rule['default']
    return templaterule


def _rule_id_from_namespaced(in_rule_id):
    return in_rule_id.split('/')[-1]


def _priority_class_to_template_name(pc):
    return PRIORITY_CLASS_INVERSE_MAP[pc]
