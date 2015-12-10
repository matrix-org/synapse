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

from ._base import SQLBaseStore
from twisted.internet import defer

import logging
import simplejson as json

logger = logging.getLogger(__name__)


class EventActionsStore(SQLBaseStore):
    @defer.inlineCallbacks
    def set_actions_for_event(self, event_id, user_id, profile_tag, actions):
        actionsJson = json.dumps(actions)

        ret = yield self.runInteraction(
            "_set_actions_for_event",
            self._simple_upsert_txn,
            EventActionsTable.table_name,
            {'event_id': event_id, 'user_id': user_id, 'profile_tag': profile_tag},
            {'actions': actionsJson}
        )
        defer.returnValue(ret)


class EventActionsTable(object):
    table_name = "event_actions"
