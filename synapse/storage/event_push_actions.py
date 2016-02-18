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
from synapse.util.caches.descriptors import cachedInlineCallbacks

import logging
import ujson as json

logger = logging.getLogger(__name__)


class EventPushActionsStore(SQLBaseStore):
    def _set_push_actions_for_event_and_users_txn(self, txn, event, tuples):
        """
        :param event: the event set actions for
        :param tuples: list of tuples of (user_id, actions)
        """
        values = []
        for uid, actions in tuples:
            values.append({
                'room_id': event.room_id,
                'event_id': event.event_id,
                'user_id': uid,
                'actions': json.dumps(actions),
                'stream_ordering': event.internal_metadata.stream_ordering,
                'topological_ordering': event.depth,
                'notif': 1,
                'highlight': 1 if _action_has_highlight(actions) else 0,
            })

        for uid, __ in tuples:
            txn.call_after(
                self.get_unread_event_push_actions_by_room_for_user.invalidate_many,
                (event.room_id, uid)
            )
        self._simple_insert_many_txn(txn, "event_push_actions", values)

    @cachedInlineCallbacks(num_args=3, lru=True, tree=True)
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
                return {"notify_count": 0, "highlight_count": 0}

            stream_ordering = results[0][0]
            topological_ordering = results[0][1]

            sql = (
                "SELECT sum(notif), sum(highlight)"
                " FROM event_push_actions ea"
                " WHERE"
                " user_id = ?"
                " AND room_id = ?"
                " AND ("
                "       topological_ordering > ?"
                "       OR (topological_ordering = ? AND stream_ordering > ?)"
                ")"
            )
            txn.execute(sql, (
                user_id, room_id,
                topological_ordering, topological_ordering, stream_ordering
            ))
            row = txn.fetchone()
            if row:
                return {
                    "notify_count": row[0] or 0,
                    "highlight_count": row[1] or 0,
                }
            else:
                return {"notify_count": 0, "highlight_count": 0}

        ret = yield self.runInteraction(
            "get_unread_event_push_actions_by_room",
            _get_unread_event_push_actions_by_room
        )
        defer.returnValue(ret)

    def _remove_push_actions_for_event_id_txn(self, txn, room_id, event_id):
        # Sad that we have to blow away the cache for the whole room here
        txn.call_after(
            self.get_unread_event_push_actions_by_room_for_user.invalidate_many,
            (room_id,)
        )
        txn.execute(
            "DELETE FROM event_push_actions WHERE room_id = ? AND event_id = ?",
            (room_id, event_id)
        )


def _action_has_highlight(actions):
    for action in actions:
        try:
            if action.get("set_tweak", None) == "highlight":
                return action.get("value", True)
        except AttributeError:
            pass

    return False
