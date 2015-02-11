# -*- coding: utf-8 -*-
# Copyright 2014 OpenMarket Ltd
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

from twisted.internet import defer

from synapse.api.errors import (
    SynapseError, Codes, UnrecognizedRequestError, NotFoundError, StoreError
)
from .base import ClientV1RestServlet, client_path_pattern
from synapse.storage.push_rule import (
    InconsistentRuleException, RuleNotFoundException
)
import synapse.push.baserules as baserules
from synapse.push.rulekinds import (
    PRIORITY_CLASS_MAP, PRIORITY_CLASS_INVERSE_MAP
)

import simplejson as json


class PushRuleRestServlet(ClientV1RestServlet):
    PATTERN = client_path_pattern("/pushrules/.*$")
    SLIGHTLY_PEDANTIC_TRAILING_SLASH_ERROR = (
        "Unrecognised request: You probably wanted a trailing slash")

    @defer.inlineCallbacks
    def on_PUT(self, request):
        spec = _rule_spec_from_path(request.postpath)
        try:
            priority_class = _priority_class_from_spec(spec)
        except InvalidRuleException as e:
            raise SynapseError(400, e.message)

        user, _ = yield self.auth.get_user_by_req(request)

        if '/' in spec['rule_id'] or '\\' in spec['rule_id']:
            raise SynapseError(400, "rule_id may not contain slashes")

        content = _parse_json(request)

        try:
            (conditions, actions) = _rule_tuple_from_request_object(
                spec['template'],
                spec['rule_id'],
                content,
                device=spec['device'] if 'device' in spec else None
            )
        except InvalidRuleException as e:
            raise SynapseError(400, e.message)

        before = request.args.get("before", None)
        if before and len(before):
            before = before[0]
        after = request.args.get("after", None)
        if after and len(after):
            after = after[0]

        try:
            yield self.hs.get_datastore().add_push_rule(
                user_name=user.to_string(),
                rule_id=_namespaced_rule_id_from_spec(spec),
                priority_class=priority_class,
                conditions=conditions,
                actions=actions,
                before=before,
                after=after
            )
        except InconsistentRuleException as e:
            raise SynapseError(400, e.message)
        except RuleNotFoundException as e:
            raise SynapseError(400, e.message)

        defer.returnValue((200, {}))

    @defer.inlineCallbacks
    def on_DELETE(self, request):
        spec = _rule_spec_from_path(request.postpath)

        user, _ = yield self.auth.get_user_by_req(request)

        namespaced_rule_id = _namespaced_rule_id_from_spec(spec)

        try:
            yield self.hs.get_datastore().delete_push_rule(
                user.to_string(), namespaced_rule_id
            )
            defer.returnValue((200, {}))
        except StoreError as e:
            if e.code == 404:
                raise NotFoundError()
            else:
                raise

    @defer.inlineCallbacks
    def on_GET(self, request):
        user, _ = yield self.auth.get_user_by_req(request)

        # we build up the full structure and then decide which bits of it
        # to send which means doing unnecessary work sometimes but is
        # is probably not going to make a whole lot of difference
        rawrules = yield self.hs.get_datastore().get_push_rules_for_user_name(
            user.to_string()
        )

        for r in rawrules:
            r["conditions"] = json.loads(r["conditions"])
            r["actions"] = json.loads(r["actions"])

        ruleslist = baserules.list_with_base_rules(rawrules, user)

        rules = {'global': {}, 'device': {}}

        rules['global'] = _add_empty_priority_class_arrays(rules['global'])

        for r in ruleslist:
            rulearray = None

            template_name = _priority_class_to_template_name(r['priority_class'])

            if r['priority_class'] > PRIORITY_CLASS_MAP['override']:
                # per-device rule
                profile_tag = _profile_tag_from_conditions(r["conditions"])
                r = _strip_device_condition(r)
                if not profile_tag:
                    continue
                if profile_tag not in rules['device']:
                    rules['device'][profile_tag] = {}
                    rules['device'][profile_tag] = (
                        _add_empty_priority_class_arrays(
                            rules['device'][profile_tag]
                        )
                    )

                rulearray = rules['device'][profile_tag][template_name]
            else:
                rulearray = rules['global'][template_name]

            template_rule = _rule_to_template(r)
            if template_rule:
                rulearray.append(template_rule)

        path = request.postpath[1:]

        if path == []:
            # we're a reference impl: pedantry is our job.
            raise UnrecognizedRequestError(
                PushRuleRestServlet.SLIGHTLY_PEDANTIC_TRAILING_SLASH_ERROR
            )

        if path[0] == '':
            defer.returnValue((200, rules))
        elif path[0] == 'global':
            path = path[1:]
            result = _filter_ruleset_with_path(rules['global'], path)
            defer.returnValue((200, result))
        elif path[0] == 'device':
            path = path[1:]
            if path == []:
                raise UnrecognizedRequestError(
                    PushRuleRestServlet.SLIGHTLY_PEDANTIC_TRAILING_SLASH_ERROR
                )
            if path[0] == '':
                defer.returnValue((200, rules['device']))

            profile_tag = path[0]
            path = path[1:]
            if profile_tag not in rules['device']:
                ret = {}
                ret = _add_empty_priority_class_arrays(ret)
                defer.returnValue((200, ret))
            ruleset = rules['device'][profile_tag]
            result = _filter_ruleset_with_path(ruleset, path)
            defer.returnValue((200, result))
        else:
            raise UnrecognizedRequestError()

    def on_OPTIONS(self, _):
        return 200, {}


def _rule_spec_from_path(path):
    if len(path) < 2:
        raise UnrecognizedRequestError()
    if path[0] != 'pushrules':
        raise UnrecognizedRequestError()

    scope = path[1]
    path = path[2:]
    if scope not in ['global', 'device']:
        raise UnrecognizedRequestError()

    device = None
    if scope == 'device':
        if len(path) == 0:
            raise UnrecognizedRequestError()
        device = path[0]
        path = path[1:]

    if len(path) == 0:
        raise UnrecognizedRequestError()

    template = path[0]
    path = path[1:]

    if len(path) == 0:
        raise UnrecognizedRequestError()

    rule_id = path[0]

    spec = {
        'scope': scope,
        'template': template,
        'rule_id': rule_id
    }
    if device:
        spec['profile_tag'] = device
    return spec


def _rule_tuple_from_request_object(rule_template, rule_id, req_obj, device=None):
    if rule_template in ['override', 'underride']:
        if 'conditions' not in req_obj:
            raise InvalidRuleException("Missing 'conditions'")
        conditions = req_obj['conditions']
        for c in conditions:
            if 'kind' not in c:
                raise InvalidRuleException("Condition without 'kind'")
    elif rule_template == 'room':
        conditions = [{
            'kind': 'event_match',
            'key': 'room_id',
            'pattern': rule_id
        }]
    elif rule_template == 'sender':
        conditions = [{
            'kind': 'event_match',
            'key': 'user_id',
            'pattern': rule_id
        }]
    elif rule_template == 'content':
        if 'pattern' not in req_obj:
            raise InvalidRuleException("Content rule missing 'pattern'")
        pat = req_obj['pattern']

        conditions = [{
            'kind': 'event_match',
            'key': 'content.body',
            'pattern': pat
        }]
    else:
        raise InvalidRuleException("Unknown rule template: %s" % (rule_template,))

    if device:
        conditions.append({
            'kind': 'device',
            'profile_tag': device
        })

    if 'actions' not in req_obj:
        raise InvalidRuleException("No actions found")
    actions = req_obj['actions']

    for a in actions:
        if a in ['notify', 'dont_notify', 'coalesce']:
            pass
        elif isinstance(a, dict) and 'set_sound' in a:
            pass
        else:
            raise InvalidRuleException("Unrecognised action")

    return conditions, actions


def _add_empty_priority_class_arrays(d):
    for pc in PRIORITY_CLASS_MAP.keys():
        d[pc] = []
    return d


def _profile_tag_from_conditions(conditions):
    """
    Given a list of conditions, return the profile tag of the
    device rule if there is one
    """
    for c in conditions:
        if c['kind'] == 'device':
            return c['profile_tag']
    return None


def _filter_ruleset_with_path(ruleset, path):
    if path == []:
        raise UnrecognizedRequestError(
            PushRuleRestServlet.SLIGHTLY_PEDANTIC_TRAILING_SLASH_ERROR
        )

    if path[0] == '':
        return ruleset
    template_kind = path[0]
    if template_kind not in ruleset:
        raise UnrecognizedRequestError()
    path = path[1:]
    if path == []:
        raise UnrecognizedRequestError(
            PushRuleRestServlet.SLIGHTLY_PEDANTIC_TRAILING_SLASH_ERROR
        )
    if path[0] == '':
        return ruleset[template_kind]
    rule_id = path[0]
    for r in ruleset[template_kind]:
        if r['rule_id'] == rule_id:
            return r
    raise NotFoundError


def _priority_class_from_spec(spec):
    if spec['template'] not in PRIORITY_CLASS_MAP.keys():
        raise InvalidRuleException("Unknown template: %s" % (spec['kind']))
    pc = PRIORITY_CLASS_MAP[spec['template']]

    if spec['scope'] == 'device':
        pc += len(PRIORITY_CLASS_MAP)

    return pc


def _priority_class_to_template_name(pc):
    if pc > PRIORITY_CLASS_MAP['override']:
        # per-device
        prio_class_index = pc - len(PushRuleRestServlet.PRIORITY_CLASS_MAP)
        return PRIORITY_CLASS_INVERSE_MAP[prio_class_index]
    else:
        return PRIORITY_CLASS_INVERSE_MAP[pc]


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


def _strip_device_condition(rule):
    for i, c in enumerate(rule['conditions']):
        if c['kind'] == 'device':
            del rule['conditions'][i]
    return rule


def _namespaced_rule_id_from_spec(spec):
    if spec['scope'] == 'global':
        scope = 'global'
    else:
        scope = 'device/%s' % (spec['profile_tag'])
    return "%s/%s/%s" % (scope, spec['template'], spec['rule_id'])


def _rule_id_from_namespaced(in_rule_id):
    return in_rule_id.split('/')[-1]


class InvalidRuleException(Exception):
    pass


# XXX: C+ped from rest/room.py - surely this should be common?
def _parse_json(request):
    try:
        content = json.loads(request.content.read())
        if type(content) != dict:
            raise SynapseError(400, "Content must be a JSON object.",
                               errcode=Codes.NOT_JSON)
        return content
    except ValueError:
        raise SynapseError(400, "Content not JSON.", errcode=Codes.NOT_JSON)


def register_servlets(hs, http_server):
    PushRuleRestServlet(hs).register(http_server)
