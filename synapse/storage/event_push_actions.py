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

from ._base import SQLBaseStore
from twisted.internet import defer

import logging
import simplejson as json

logger = logging.getLogger(__name__)


class EventPushActionsStore(SQLBaseStore):
    @defer.inlineCallbacks
    def set_push_actions_for_event_and_users(self, event, tuples):
        """
        :param event: the event set actions for
        :param tuples: list of tuples of (user_id, profile_tag, actions)
        """
        values = []
        for uid, profile_tag, actions in tuples:
            values.append({
                'room_id': event['room_id'],
                'event_id': event['event_id'],
                'user_id': uid,
                'profile_tag': profile_tag,
                'actions': json.dumps(actions)
            })

        yield self.runInteraction(
            "set_actions_for_event_and_users",
            self._simple_insert_many_txn,
            EventPushActionsTable.table_name,
            values
        )

    @defer.inlineCallbacks
    def get_unread_event_push_actions_by_room_for_user(
            self, room_id, user_id, last_read_event_id
    ):
        def _get_unread_event_push_actions_by_room(txn):
            sql = (
                "SELECT stream_ordering, topological_ordering"
                " FROM events"
                " WHERE room_id = ? AND event_id = ?"
            )
            txn.execute(
                sql, (room_id, last_read_event_id)
            )
            results = txn.fetchall()
            if len(results) == 0:
                return []

            stream_ordering = results[0][0]
            topological_ordering = results[0][1]

            sql = (
                "SELECT ea.event_id, ea.actions"
                " FROM event_push_actions ea, events e"
                " WHERE ea.room_id = e.room_id"
                " AND ea.event_id = e.event_id"
                " AND ea.user_id = ?"
                " AND ea.room_id = ?"
                " AND ("
                "       e.topological_ordering > ?"
                "       OR (e.topological_ordering = ? AND e.stream_ordering > ?)"
                ")"
            )
            txn.execute(sql, (
                user_id, room_id,
                topological_ordering, topological_ordering, stream_ordering
            )
            )
            return [
                {"event_id": row[0], "actions": row[1]} for row in txn.fetchall()
            ]

        ret = yield self.runInteraction(
            "get_unread_event_push_actions_by_room",
            _get_unread_event_push_actions_by_room
        )
        defer.returnValue(ret)


class EventPushActionsTable(object):
    table_name = "event_push_actions"
