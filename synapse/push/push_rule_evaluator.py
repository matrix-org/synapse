# -*- coding: utf-8 -*-
# Copyright 2015 OpenMarket Ltd
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

from synapse.types import UserID

import baserules

import logging
import simplejson as json
import re

logger = logging.getLogger(__name__)


@defer.inlineCallbacks
def evaluator_for_user_name_and_profile_tag(user_name, profile_tag, room_id, store):
    rawrules = yield store.get_push_rules_for_user(user_name)
    enabled_map = yield store.get_push_rules_enabled_for_user(user_name)
    our_member_event = yield store.get_current_state(
        room_id=room_id,
        event_type='m.room.member',
        state_key=user_name,
    )

    defer.returnValue(PushRuleEvaluator(
        user_name, profile_tag, rawrules, enabled_map,
        room_id, our_member_event, store
    ))


class PushRuleEvaluator:
    DEFAULT_ACTIONS = []
    INEQUALITY_EXPR = re.compile("^([=<>]*)([0-9]*)$")

    def __init__(self, user_name, profile_tag, raw_rules, enabled_map, room_id,
                 our_member_event, store):
        self.user_name = user_name
        self.profile_tag = profile_tag
        self.room_id = room_id
        self.our_member_event = our_member_event
        self.store = store

        rules = []
        for raw_rule in raw_rules:
            rule = dict(raw_rule)
            rule['conditions'] = json.loads(raw_rule['conditions'])
            rule['actions'] = json.loads(raw_rule['actions'])
            rules.append(rule)

        user = UserID.from_string(self.user_name)
        self.rules = baserules.list_with_base_rules(rules, user)

        self.enabled_map = enabled_map

    @staticmethod
    def tweaks_for_actions(actions):
        tweaks = {}
        for a in actions:
            if not isinstance(a, dict):
                continue
            if 'set_tweak' in a and 'value' in a:
                tweaks[a['set_tweak']] = a['value']
        return tweaks

    @defer.inlineCallbacks
    def actions_for_event(self, ev):
        """
        This should take into account notification settings that the user
        has configured both globally and per-room when we have the ability
        to do such things.
        """
        if ev['user_id'] == self.user_name:
            # let's assume you probably know about messages you sent yourself
            defer.returnValue([])

        room_id = ev['room_id']

        # get *our* member event for display name matching
        my_display_name = None

        if self.our_member_event:
            my_display_name = self.our_member_event[0].content.get("displayname")

        room_members = yield self.store.get_users_in_room(room_id)
        room_member_count = len(room_members)

        for r in self.rules:
            if r['rule_id'] in self.enabled_map:
                r['enabled'] = self.enabled_map[r['rule_id']]
            elif 'enabled' not in r:
                r['enabled'] = True
            if not r['enabled']:
                continue
            matches = True

            conditions = r['conditions']
            actions = r['actions']

            for c in conditions:
                matches &= self._event_fulfills_condition(
                    ev, c, display_name=my_display_name,
                    room_member_count=room_member_count,
                    profile_tag=self.profile_tag
                )
            logger.debug(
                "Rule %s %s",
                r['rule_id'], "matches" if matches else "doesn't match"
            )
            # ignore rules with no actions (we have an explict 'dont_notify')
            if len(actions) == 0:
                logger.warn(
                    "Ignoring rule id %s with no actions for user %s",
                    r['rule_id'], self.user_name
                )
                continue
            if matches:
                logger.info(
                    "%s matches for user %s, event %s",
                    r['rule_id'], self.user_name, ev['event_id']
                )

                # filter out dont_notify as we treat an empty actions list
                # as dont_notify, and this doesn't take up a row in our database
                actions = [x for x in actions if x != 'dont_notify']

                defer.returnValue(actions)

        logger.info(
            "No rules match for user %s, event %s",
            self.user_name, ev['event_id']
        )
        defer.returnValue(PushRuleEvaluator.DEFAULT_ACTIONS)

    @staticmethod
    def _glob_to_regexp(glob):
        r = re.escape(glob)
        r = re.sub(r'\\\*', r'.*?', r)
        r = re.sub(r'\\\?', r'.', r)

        # handle [abc], [a-z] and [!a-z] style ranges.
        r = re.sub(r'\\\[(\\\!|)(.*)\\\]',
                   lambda x: ('[%s%s]' % (x.group(1) and '^' or '',
                                          re.sub(r'\\\-', '-', x.group(2)))), r)
        return r

    @staticmethod
    def _event_fulfills_condition(ev, condition,
                                  display_name, room_member_count, profile_tag):
        if condition['kind'] == 'event_match':
            if 'pattern' not in condition:
                logger.warn("event_match condition with no pattern")
                return False
            # XXX: optimisation: cache our pattern regexps
            if condition['key'] == 'content.body':
                r = r'\b%s\b' % PushRuleEvaluator._glob_to_regexp(condition['pattern'])
            else:
                r = r'^%s$' % PushRuleEvaluator._glob_to_regexp(condition['pattern'])
            val = _value_for_dotted_key(condition['key'], ev)
            if val is None:
                return False
            return re.search(r, val, flags=re.IGNORECASE) is not None

        elif condition['kind'] == 'device':
            if 'profile_tag' not in condition:
                return True
            return condition['profile_tag'] == profile_tag

        elif condition['kind'] == 'contains_display_name':
            # This is special because display names can be different
            # between rooms and so you can't really hard code it in a rule.
            # Optimisation: we should cache these names and update them from
            # the event stream.
            if 'content' not in ev or 'body' not in ev['content']:
                return False
            if not display_name:
                return False
            return re.search(
                r"\b%s\b" % re.escape(display_name), ev['content']['body'],
                flags=re.IGNORECASE
            ) is not None

        elif condition['kind'] == 'room_member_count':
            if 'is' not in condition:
                return False
            m = PushRuleEvaluator.INEQUALITY_EXPR.match(condition['is'])
            if not m:
                return False
            ineq = m.group(1)
            rhs = m.group(2)
            if not rhs.isdigit():
                return False
            rhs = int(rhs)

            if ineq == '' or ineq == '==':
                return room_member_count == rhs
            elif ineq == '<':
                return room_member_count < rhs
            elif ineq == '>':
                return room_member_count > rhs
            elif ineq == '>=':
                return room_member_count >= rhs
            elif ineq == '<=':
                return room_member_count <= rhs
            else:
                return False
        else:
            return True


def _value_for_dotted_key(dotted_key, event):
    parts = dotted_key.split(".")
    val = event
    while len(parts) > 0:
        if parts[0] not in val:
            return None
        val = val[parts[0]]
        parts = parts[1:]
    return val
