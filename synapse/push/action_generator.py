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

from synapse.util.metrics import Measure

from .bulk_push_rule_evaluator import BulkPushRuleEvaluator

logger = logging.getLogger(__name__)


class ActionGenerator:
    def __init__(self, hs):
        self.hs = hs
        self.clock = hs.get_clock()
        self.store = hs.get_datastore()
        self.bulk_evaluator = BulkPushRuleEvaluator(hs)
        # really we want to get all user ids and all profile tags too,
        # since we want the actions for each profile tag for every user and
        # also actions for a client with no profile tag for each user.
        # Currently the event stream doesn't support profile tags on an
        # event stream, so we just run the rules for a client with no profile
        # tag (ie. we just need all the users).

    async def handle_push_actions_for_event(self, event, context):
        with Measure(self.clock, "action_for_event_by_user"):
            await self.bulk_evaluator.action_for_event_by_user(event, context)
