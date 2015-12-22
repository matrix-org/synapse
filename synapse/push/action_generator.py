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

import bulk_push_rule_evaluator

import logging

logger = logging.getLogger(__name__)


class ActionGenerator:
    def __init__(self, hs, store):
        self.hs = hs
        self.store = store
        # really we want to get all user ids and all profile tags too,
        # since we want the actions for each profile tag for every user and
        # also actions for a client with no profile tag for each user.
        # Currently the event stream doesn't support profile tags on an
        # event stream, so we just run the rules for a client with no profile
        # tag (ie. we just need all the users).

    @defer.inlineCallbacks
    def handle_event(self, event):
        users = yield self.store.get_users_in_room(event['room_id'])

        bulk_evaluator = yield bulk_push_rule_evaluator.evaluator_for_room_id(
            event['room_id'], self.hs, self.store
        )

        actions_by_user = bulk_evaluator.action_for_event_by_user(event)

        yield self.store.set_actions_for_event_and_users(
            event,
            [
                (uid, None, actions) for uid, actions in actions_by_user.items()
            ]
        )
