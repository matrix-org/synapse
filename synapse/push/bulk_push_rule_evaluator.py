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

from twisted.internet import defer

from .push_rule_evaluator import PushRuleEvaluatorForEvent

from synapse.api.constants import EventTypes, Membership
from synapse.visibility import filter_events_for_clients


logger = logging.getLogger(__name__)


@defer.inlineCallbacks
def _get_rules(room_id, user_ids, store):
    rules_by_user = yield store.bulk_get_push_rules(user_ids)

    rules_by_user = {k: v for k, v in rules_by_user.items() if v is not None}

    defer.returnValue(rules_by_user)


@defer.inlineCallbacks
def evaluator_for_event(event, hs, store, current_state):
    room_id = event.room_id
    # We also will want to generate notifs for other people in the room so
    # their unread countss are correct in the event stream, but to avoid
    # generating them for bot / AS users etc, we only do so for people who've
    # sent a read receipt into the room.

    local_users_in_room = set(
        e.state_key for e in current_state.values()
        if e.type == EventTypes.Member and e.membership == Membership.JOIN
        and hs.is_mine_id(e.state_key)
    )

    # users in the room who have pushers need to get push rules run because
    # that's how their pushers work
    if_users_with_pushers = yield store.get_if_users_have_pushers(
        local_users_in_room
    )
    user_ids = set(
        uid for uid, have_pusher in if_users_with_pushers.items() if have_pusher
    )

    users_with_receipts = yield store.get_users_with_read_receipts_in_room(room_id)

    # any users with pushers must be ours: they have pushers
    for uid in users_with_receipts:
        if uid in local_users_in_room:
            user_ids.add(uid)

    # if this event is an invite event, we may need to run rules for the user
    # who's been invited, otherwise they won't get told they've been invited
    if event.type == 'm.room.member' and event.content['membership'] == 'invite':
        invited_user = event.state_key
        if invited_user and hs.is_mine_id(invited_user):
            has_pusher = yield store.user_has_pusher(invited_user)
            if has_pusher:
                user_ids.add(invited_user)

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
    def action_for_event_by_user(self, event, current_state):
        actions_by_user = {}

        # None of these users can be peeking since this list of users comes
        # from the set of users in the room, so we know for sure they're all
        # actually in the room.
        user_tuples = [
            (u, False) for u in self.rules_by_user.keys()
        ]

        filtered_by_user = yield filter_events_for_clients(
            self.store, user_tuples, [event], {event.event_id: current_state}
        )

        room_members = set(
            e.state_key for e in current_state.values()
            if e.type == EventTypes.Member and e.membership == Membership.JOIN
        )

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
