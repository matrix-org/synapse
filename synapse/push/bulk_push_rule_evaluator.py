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
import ujson as json

from twisted.internet import defer

from .baserules import list_with_base_rules
from .push_rule_evaluator import PushRuleEvaluatorForEvent

from synapse.api.constants import EventTypes


logger = logging.getLogger(__name__)


def decode_rule_json(rule):
    rule['conditions'] = json.loads(rule['conditions'])
    rule['actions'] = json.loads(rule['actions'])
    return rule


@defer.inlineCallbacks
def _get_rules(room_id, user_ids, store):
    rules_by_user = yield store.bulk_get_push_rules(user_ids)
    rules_enabled_by_user = yield store.bulk_get_push_rules_enabled(user_ids)

    rules_by_user = {
        uid: list_with_base_rules([
            decode_rule_json(rule_list)
            for rule_list in rules_by_user.get(uid, [])
        ])
        for uid in user_ids
    }

    # We apply the rules-enabled map here: bulk_get_push_rules doesn't
    # fetch disabled rules, but this won't account for any server default
    # rules the user has disabled, so we need to do this too.
    for uid in user_ids:
        if uid not in rules_enabled_by_user:
            continue

        user_enabled_map = rules_enabled_by_user[uid]

        for i, rule in enumerate(rules_by_user[uid]):
            rule_id = rule['rule_id']

            if rule_id in user_enabled_map:
                if rule.get('enabled', True) != bool(user_enabled_map[rule_id]):
                    # Rules are cached across users.
                    rule = dict(rule)
                    rule['enabled'] = bool(user_enabled_map[rule_id])
                    rules_by_user[uid][i] = rule

    defer.returnValue(rules_by_user)


@defer.inlineCallbacks
def evaluator_for_event(event, hs, store):
    room_id = event.room_id

    # users in the room who have pushers need to get push rules run because
    # that's how their pushers work
    users_with_pushers = yield store.get_users_with_pushers_in_room(room_id)

    # We also will want to generate notifs for other people in the room so
    # their unread countss are correct in the event stream, but to avoid
    # generating them for bot / AS users etc, we only do so for people who've
    # sent a read receipt into the room.

    all_in_room = yield store.get_users_in_room(room_id)
    all_in_room = set(all_in_room)

    receipts = yield store.get_receipts_for_room(room_id, "m.read")

    # any users with pushers must be ours: they have pushers
    user_ids = set(users_with_pushers)
    for r in receipts:
        if hs.is_mine_id(r['user_id']) and r['user_id'] in all_in_room:
            user_ids.add(r['user_id'])

    # if this event is an invite event, we may need to run rules for the user
    # who's been invited, otherwise they won't get told they've been invited
    if event.type == 'm.room.member' and event.content['membership'] == 'invite':
        invited_user = event.state_key
        if invited_user and hs.is_mine_id(invited_user):
            has_pusher = yield store.user_has_pusher(invited_user)
            if has_pusher:
                user_ids.add(invited_user)

    user_ids = list(user_ids)

    rules_by_user = yield _get_rules(room_id, user_ids, store)

    defer.returnValue(BulkPushRuleEvaluator(
        room_id, rules_by_user, user_ids, store
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
    def __init__(self, room_id, rules_by_user, users_in_room, store):
        self.room_id = room_id
        self.rules_by_user = rules_by_user
        self.users_in_room = users_in_room
        self.store = store

    @defer.inlineCallbacks
    def action_for_event_by_user(self, event, handler, current_state):
        actions_by_user = {}

        # None of these users can be peeking since this list of users comes
        # from the set of users in the room, so we know for sure they're all
        # actually in the room.
        user_tuples = [
            (u, False) for u in self.rules_by_user.keys()
        ]

        filtered_by_user = yield handler.filter_events_for_clients(
            user_tuples, [event], {event.event_id: current_state}
        )

        room_members = yield self.store.get_users_in_room(self.room_id)

        evaluator = PushRuleEvaluatorForEvent(event, len(room_members))

        condition_cache = {}

        display_names = {}
        for ev in current_state.values():
            nm = ev.content.get("displayname", None)
            if nm and ev.type == EventTypes.Member:
                display_names[ev.state_key] = nm

        for uid, rules in self.rules_by_user.items():
            display_name = display_names.get(uid, None)

            filtered = filtered_by_user[uid]
            if len(filtered) == 0:
                continue

            if filtered[0].sender == uid:
                continue

            for rule in rules:
                if 'enabled' in rule and not rule['enabled']:
                    continue

                matches = _condition_checker(
                    evaluator, rule['conditions'], uid, display_name, condition_cache
                )
                if matches:
                    actions = [x for x in rule['actions'] if x != 'dont_notify']
                    if actions and 'notify' in actions:
                        actions_by_user[uid] = actions
                    break
        defer.returnValue(actions_by_user)


def _condition_checker(evaluator, conditions, uid, display_name, cache):
    for cond in conditions:
        _id = cond.get("_id", None)
        if _id:
            res = cache.get(_id, None)
            if res is False:
                return False
            elif res is True:
                continue

        res = evaluator.matches(cond, uid, display_name)
        if _id:
            cache[_id] = bool(res)

        if not res:
            return False

    return True
