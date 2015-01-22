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

from synapse.api.errors import SynapseError, Codes, UnrecognizedRequestError
from base import RestServlet, client_path_pattern
from synapse.storage.push_rule import InconsistentRuleException, RuleNotFoundException

import json


class PushRuleRestServlet(RestServlet):
    PATTERN = client_path_pattern("/pushrules/.*$")

    def rule_spec_from_path(self, path):
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
            'scope' : scope,
            'template': template,
            'rule_id': rule_id
        }
        if device:
            spec['device'] = device
        return spec

    def rule_tuple_from_request_object(self, rule_template, rule_id, req_obj):
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
            conditions = [{
                'kind': 'event_match',
                'key': 'content.body',
                'pattern': req_obj['pattern']
            }]
        else:
            raise InvalidRuleException("Unknown rule template: %s" % (rule_template))

        if 'actions' not in req_obj:
            raise InvalidRuleException("No actions found")
        actions = req_obj['actions']

        for a in actions:
            if a in ['notify', 'dont-notify', 'coalesce']:
                pass
            elif isinstance(a, dict) and 'set_sound' in a:
                pass
            else:
                raise InvalidRuleException("Unrecognised action")

        return (conditions, actions)

    def priority_class_from_spec(self, spec):
        map = {
            'underride': 0,
            'sender': 1,
            'room': 2,
            'content': 3,
            'override': 4
        }

        if spec['template'] not in map.keys():
            raise InvalidRuleException("Unknown template: %s" % (spec['kind']))
        pc = map[spec['template']]

        if spec['scope'] == 'device':
            pc += 5

        return pc

    @defer.inlineCallbacks
    def on_PUT(self, request):
        spec = self.rule_spec_from_path(request.postpath)
        try:
            priority_class = self.priority_class_from_spec(spec)
        except InvalidRuleException as e:
            raise SynapseError(400, e.message)

        user = yield self.auth.get_user_by_req(request)

        content = _parse_json(request)

        try:
            (conditions, actions) = self.rule_tuple_from_request_object(
                spec['template'],
                spec['rule_id'],
                content
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
                rule_id=spec['rule_id'],
                priority_class=priority_class,
                conditions=conditions,
                actions=actions,
                before=before,
                after=after
            )
        except InconsistentRuleException as e:
            raise SynapseError(400, e.message)
        except RuleNotFoundException:
            raise SynapseError(400, "before/after rule not found")

        defer.returnValue((200, {}))

    def on_OPTIONS(self, _):
        return 200, {}


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
