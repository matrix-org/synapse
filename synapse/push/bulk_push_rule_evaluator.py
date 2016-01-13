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

import logging
import simplejson as json

from twisted.internet import defer

from synapse.types import UserID

import baserules
from push_rule_evaluator import PushRuleEvaluator

from synapse.events.utils import serialize_event

logger = logging.getLogger(__name__)


def decode_rule_json(rule):
    rule['conditions'] = json.loads(rule['conditions'])
    rule['actions'] = json.loads(rule['actions'])
    return rule


@defer.inlineCallbacks
def evaluator_for_room_id(room_id, store):
    users = yield store.get_users_in_room(room_id)
    rules_by_user = yield store.bulk_get_push_rules(users)
    rules_by_user = {
        uid: baserules.list_with_base_rules(
            [decode_rule_json(rule_list) for rule_list in rules_by_user[uid]]
            if uid in rules_by_user else [],
            UserID.from_string(uid),
        )
        for uid in users
    }
    member_events = yield store.get_current_state(
        room_id=room_id,
        event_type='m.room.member',
    )
    display_names = {}
    for ev in member_events:
        if ev.content.get("displayname"):
            display_names[ev.state_key] = ev.content.get("displayname")

    defer.returnValue(BulkPushRuleEvaluator(
        room_id, rules_by_user, display_names, users, store
    ))


class BulkPushRuleEvaluator:
    """
    Runs push rules for all users in a room.
    This is faster than running PushRuleEvaluator for each user because it
    fetches all the rules for all the users in one (batched) db query
    rather than doing multiple queries per-user. It currently uses
    the same logic to run the actual rules, but could be optimised further
    (see https://matrix.org/jira/browse/SYN-562)
    """
    def __init__(self, room_id, rules_by_user, display_names, users_in_room, store):
        self.room_id = room_id
        self.rules_by_user = rules_by_user
        self.display_names = display_names
        self.users_in_room = users_in_room
        self.store = store

    @defer.inlineCallbacks
    def action_for_event_by_user(self, event, handler):
        actions_by_user = {}

        for uid, rules in self.rules_by_user.items():
            display_name = None
            if uid in self.display_names:
                display_name = self.display_names[uid]

            is_guest = yield self.store.is_guest(UserID.from_string(uid))
            filtered = yield handler._filter_events_for_client(
                uid, [event], is_guest=is_guest
            )
            if len(filtered) == 0:
                continue

            for rule in rules:
                try:
                    if 'enabled' in rule and not rule['enabled']:
                        continue

                    # XXX: profile tags
                    if BulkPushRuleEvaluator.event_matches_rule(
                        event, rule,
                        display_name, len(self.users_in_room), None
                    ):
                        actions = [x for x in rule['actions'] if x != 'dont_notify']
                        if len(actions) > 0:
                            actions_by_user[uid] = actions
                        break
                except:
                    logger.exception("Failed to handle rule %r", rule)
        defer.returnValue(actions_by_user)

    @staticmethod
    def event_matches_rule(event, rule,
                           display_name, room_member_count, profile_tag):
        matches = True

        # passing the clock all the way into here is extremely awkward and push
        # rules do not care about any of the relative timestamps, so we just
        # pass 0 for the current time.
        client_event = serialize_event(event, 0)

        for cond in rule['conditions']:
            matches &= PushRuleEvaluator._event_fulfills_condition(
                client_event, cond, display_name, room_member_count, profile_tag
            )
        return matches
