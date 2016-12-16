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

from synapse.api.constants import EventTypes
from synapse.visibility import filter_events_for_clients_context


logger = logging.getLogger(__name__)


@defer.inlineCallbacks
def evaluator_for_event(event, hs, store, context):
    rules_by_user = yield store.bulk_get_push_rules_for_room(
        event, context
    )

    # if this event is an invite event, we may need to run rules for the user
    # who's been invited, otherwise they won't get told they've been invited
    if event.type == 'm.room.member' and event.content['membership'] == 'invite':
        invited_user = event.state_key
        if invited_user and hs.is_mine_id(invited_user):
            has_pusher = yield store.user_has_pusher(invited_user)
            if has_pusher:
                rules_by_user = dict(rules_by_user)
                rules_by_user[invited_user] = yield store.get_push_rules_for_user(
                    invited_user
                )

    defer.returnValue(BulkPushRuleEvaluator(
        event.room_id, rules_by_user, store
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
    def __init__(self, room_id, rules_by_user, store):
        self.room_id = room_id
        self.rules_by_user = rules_by_user
        self.store = store

    @defer.inlineCallbacks
    def action_for_event_by_user(self, event, context):
        actions_by_user = {}

        # None of these users can be peeking since this list of users comes
        # from the set of users in the room, so we know for sure they're all
        # actually in the room.
        user_tuples = [
            (u, False) for u in self.rules_by_user.keys()
        ]

        filtered_by_user = yield filter_events_for_clients_context(
            self.store, user_tuples, [event], {event.event_id: context}
        )

        room_members = yield self.store.get_joined_users_from_context(
            event, context
        )

        evaluator = PushRuleEvaluatorForEvent(event, len(room_members))

        condition_cache = {}

        for uid, rules in self.rules_by_user.items():
            display_name = room_members.get(uid, {}).get("display_name", None)
            if not display_name:
                # Handle the case where we are pushing a membership event to
                # that user, as they might not be already joined.
                if event.type == EventTypes.Member and event.state_key == uid:
                    display_name = event.content.get("displayname", None)

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
