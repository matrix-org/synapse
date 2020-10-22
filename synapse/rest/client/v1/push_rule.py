# -*- coding: utf-8 -*-
# Copyright 2014-2016 OpenMarket Ltd
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

from synapse.api.errors import (
    NotFoundError,
    StoreError,
    SynapseError,
    UnrecognizedRequestError,
)
from synapse.http.servlet import (
    RestServlet,
    parse_json_value_from_request,
    parse_string,
)
from synapse.push.baserules import BASE_RULE_IDS, NEW_RULE_IDS
from synapse.push.clientformat import format_push_rules_for_user
from synapse.push.rulekinds import PRIORITY_CLASS_MAP
from synapse.rest.client.v2_alpha._base import client_patterns
from synapse.storage.push_rule import InconsistentRuleException, RuleNotFoundException


class PushRuleRestServlet(RestServlet):
    PATTERNS = client_patterns("/(?P<path>pushrules/.*)$", v1=True)
    SLIGHTLY_PEDANTIC_TRAILING_SLASH_ERROR = (
        "Unrecognised request: You probably wanted a trailing slash"
    )

    def __init__(self, hs):
        super().__init__()
        self.auth = hs.get_auth()
        self.store = hs.get_datastore()
        self.notifier = hs.get_notifier()
        self._is_worker = hs.config.worker_app is not None

        self._users_new_default_push_rules = hs.config.users_new_default_push_rules

    async def on_PUT(self, request, path):
        if self._is_worker:
            raise Exception("Cannot handle PUT /push_rules on worker")

        spec = _rule_spec_from_path(path.split("/"))
        try:
            priority_class = _priority_class_from_spec(spec)
        except InvalidRuleException as e:
            raise SynapseError(400, str(e))

        requester = await self.auth.get_user_by_req(request)

        if "/" in spec["rule_id"] or "\\" in spec["rule_id"]:
            raise SynapseError(400, "rule_id may not contain slashes")

        content = parse_json_value_from_request(request)

        user_id = requester.user.to_string()

        if "attr" in spec:
            await self.set_rule_attr(user_id, spec, content)
            self.notify_user(user_id)
            return 200, {}

        if spec["rule_id"].startswith("."):
            # Rule ids starting with '.' are reserved for server default rules.
            raise SynapseError(400, "cannot add new rule_ids that start with '.'")

        try:
            (conditions, actions) = _rule_tuple_from_request_object(
                spec["template"], spec["rule_id"], content
            )
        except InvalidRuleException as e:
            raise SynapseError(400, str(e))

        before = parse_string(request, "before")
        if before:
            before = _namespaced_rule_id(spec, before)

        after = parse_string(request, "after")
        if after:
            after = _namespaced_rule_id(spec, after)

        try:
            await self.store.add_push_rule(
                user_id=user_id,
                rule_id=_namespaced_rule_id_from_spec(spec),
                priority_class=priority_class,
                conditions=conditions,
                actions=actions,
                before=before,
                after=after,
            )
            self.notify_user(user_id)
        except InconsistentRuleException as e:
            raise SynapseError(400, str(e))
        except RuleNotFoundException as e:
            raise SynapseError(400, str(e))

        return 200, {}

    async def on_DELETE(self, request, path):
        if self._is_worker:
            raise Exception("Cannot handle DELETE /push_rules on worker")

        spec = _rule_spec_from_path(path.split("/"))

        requester = await self.auth.get_user_by_req(request)
        user_id = requester.user.to_string()

        namespaced_rule_id = _namespaced_rule_id_from_spec(spec)

        try:
            await self.store.delete_push_rule(user_id, namespaced_rule_id)
            self.notify_user(user_id)
            return 200, {}
        except StoreError as e:
            if e.code == 404:
                raise NotFoundError()
            else:
                raise

    async def on_GET(self, request, path):
        requester = await self.auth.get_user_by_req(request)
        user_id = requester.user.to_string()

        # we build up the full structure and then decide which bits of it
        # to send which means doing unnecessary work sometimes but is
        # is probably not going to make a whole lot of difference
        rules = await self.store.get_push_rules_for_user(user_id)

        rules = format_push_rules_for_user(requester.user, rules)

        path = path.split("/")[1:]

        if path == []:
            # we're a reference impl: pedantry is our job.
            raise UnrecognizedRequestError(
                PushRuleRestServlet.SLIGHTLY_PEDANTIC_TRAILING_SLASH_ERROR
            )

        if path[0] == "":
            return 200, rules
        elif path[0] == "global":
            result = _filter_ruleset_with_path(rules["global"], path[1:])
            return 200, result
        else:
            raise UnrecognizedRequestError()

    def notify_user(self, user_id):
        stream_id = self.store.get_max_push_rules_stream_id()
        self.notifier.on_new_event("push_rules_key", stream_id, users=[user_id])

    async def set_rule_attr(self, user_id, spec, val):
        if spec["attr"] not in ("enabled", "actions"):
            # for the sake of potential future expansion, shouldn't report
            # 404 in the case of an unknown request so check it corresponds to
            # a known attribute first.
            raise UnrecognizedRequestError()

        namespaced_rule_id = _namespaced_rule_id_from_spec(spec)
        rule_id = spec["rule_id"]
        is_default_rule = rule_id.startswith(".")
        if is_default_rule:
            if namespaced_rule_id not in BASE_RULE_IDS:
                raise NotFoundError("Unknown rule %s" % (namespaced_rule_id,))
        if spec["attr"] == "enabled":
            if isinstance(val, dict) and "enabled" in val:
                val = val["enabled"]
            if not isinstance(val, bool):
                # Legacy fallback
                # This should *actually* take a dict, but many clients pass
                # bools directly, so let's not break them.
                raise SynapseError(400, "Value for 'enabled' must be boolean")
            return await self.store.set_push_rule_enabled(
                user_id, namespaced_rule_id, val, is_default_rule
            )
        elif spec["attr"] == "actions":
            actions = val.get("actions")
            _check_actions(actions)
            namespaced_rule_id = _namespaced_rule_id_from_spec(spec)
            rule_id = spec["rule_id"]
            is_default_rule = rule_id.startswith(".")
            if is_default_rule:
                if user_id in self._users_new_default_push_rules:
                    rule_ids = NEW_RULE_IDS
                else:
                    rule_ids = BASE_RULE_IDS

                if namespaced_rule_id not in rule_ids:
                    raise SynapseError(404, "Unknown rule %r" % (namespaced_rule_id,))
            return await self.store.set_push_rule_actions(
                user_id, namespaced_rule_id, actions, is_default_rule
            )
        else:
            raise UnrecognizedRequestError()


def _rule_spec_from_path(path):
    """Turn a sequence of path components into a rule spec

    Args:
        path (sequence[unicode]): the URL path components.

    Returns:
        dict: rule spec dict, containing scope/template/rule_id entries,
            and possibly attr.

    Raises:
        UnrecognizedRequestError if the path components cannot be parsed.
    """
    if len(path) < 2:
        raise UnrecognizedRequestError()
    if path[0] != "pushrules":
        raise UnrecognizedRequestError()

    scope = path[1]
    path = path[2:]
    if scope != "global":
        raise UnrecognizedRequestError()

    if len(path) == 0:
        raise UnrecognizedRequestError()

    template = path[0]
    path = path[1:]

    if len(path) == 0 or len(path[0]) == 0:
        raise UnrecognizedRequestError()

    rule_id = path[0]

    spec = {"scope": scope, "template": template, "rule_id": rule_id}

    path = path[1:]

    if len(path) > 0 and len(path[0]) > 0:
        spec["attr"] = path[0]

    return spec


def _rule_tuple_from_request_object(rule_template, rule_id, req_obj):
    if rule_template in ["override", "underride"]:
        if "conditions" not in req_obj:
            raise InvalidRuleException("Missing 'conditions'")
        conditions = req_obj["conditions"]
        for c in conditions:
            if "kind" not in c:
                raise InvalidRuleException("Condition without 'kind'")
    elif rule_template == "room":
        conditions = [{"kind": "event_match", "key": "room_id", "pattern": rule_id}]
    elif rule_template == "sender":
        conditions = [{"kind": "event_match", "key": "user_id", "pattern": rule_id}]
    elif rule_template == "content":
        if "pattern" not in req_obj:
            raise InvalidRuleException("Content rule missing 'pattern'")
        pat = req_obj["pattern"]

        conditions = [{"kind": "event_match", "key": "content.body", "pattern": pat}]
    else:
        raise InvalidRuleException("Unknown rule template: %s" % (rule_template,))

    if "actions" not in req_obj:
        raise InvalidRuleException("No actions found")
    actions = req_obj["actions"]

    _check_actions(actions)

    return conditions, actions


def _check_actions(actions):
    if not isinstance(actions, list):
        raise InvalidRuleException("No actions found")

    for a in actions:
        if a in ["notify", "dont_notify", "coalesce"]:
            pass
        elif isinstance(a, dict) and "set_tweak" in a:
            pass
        else:
            raise InvalidRuleException("Unrecognised action")


def _filter_ruleset_with_path(ruleset, path):
    if path == []:
        raise UnrecognizedRequestError(
            PushRuleRestServlet.SLIGHTLY_PEDANTIC_TRAILING_SLASH_ERROR
        )

    if path[0] == "":
        return ruleset
    template_kind = path[0]
    if template_kind not in ruleset:
        raise UnrecognizedRequestError()
    path = path[1:]
    if path == []:
        raise UnrecognizedRequestError(
            PushRuleRestServlet.SLIGHTLY_PEDANTIC_TRAILING_SLASH_ERROR
        )
    if path[0] == "":
        return ruleset[template_kind]
    rule_id = path[0]

    the_rule = None
    for r in ruleset[template_kind]:
        if r["rule_id"] == rule_id:
            the_rule = r
    if the_rule is None:
        raise NotFoundError

    path = path[1:]
    if len(path) == 0:
        return the_rule

    attr = path[0]
    if attr in the_rule:
        # Make sure we return a JSON object as the attribute may be a
        # JSON value.
        return {attr: the_rule[attr]}
    else:
        raise UnrecognizedRequestError()


def _priority_class_from_spec(spec):
    if spec["template"] not in PRIORITY_CLASS_MAP.keys():
        raise InvalidRuleException("Unknown template: %s" % (spec["template"]))
    pc = PRIORITY_CLASS_MAP[spec["template"]]

    return pc


def _namespaced_rule_id_from_spec(spec):
    return _namespaced_rule_id(spec, spec["rule_id"])


def _namespaced_rule_id(spec, rule_id):
    return "global/%s/%s" % (spec["template"], rule_id)


class InvalidRuleException(Exception):
    pass


def register_servlets(hs, http_server):
    PushRuleRestServlet(hs).register(http_server)
