# -*- coding: utf-8 -*-
# Copyright 2016 OpenMarket Ltd
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


from .events import SlavedEventStore
from .receipts import SlavedReceiptsStore

from synapse.storage import DataStore
from synapse.storage.event_push_actions import EventPushActionsStore


class SlavedPushActionsStore(SlavedEventStore, SlavedReceiptsStore):
    get_unread_event_push_actions_by_room_for_user = (
        EventPushActionsStore.__dict__["get_unread_event_push_actions_by_room_for_user"]
    )

    get_unread_push_actions_for_user_in_range = (
        DataStore.get_unread_push_actions_for_user_in_range.__func__
    )

    get_push_action_users_in_range = (
        DataStore.get_push_action_users_in_range.__func__
    )

    def invalidate_caches_for_event(self, event, backfilled, reset_state):
        self.get_unread_event_push_actions_by_room_for_user.invalidate_many(
            (event.room_id,)
        )
        super(SlavedPushActionsStore, self).invalidate_caches_for_event(
            event, backfilled, reset_state
        )

    def invalidate_caches_for_receipt(self, room_id, receipt_type, user_id):
        self.get_unread_event_push_actions_by_room_for_user.invalidate_many(
            (room_id,)
        )
        super(SlavedPushActionsStore, self).invalidate_caches_for_receipt(
            room_id, receipt_type, user_id
        )
