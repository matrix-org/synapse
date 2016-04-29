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
        Args:
            event: the event set actions for
            tuples: list of tuples of (user_id, actions)
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

    @cachedInlineCallbacks(num_args=3, lru=True, tree=True, max_entries=5000)
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

    @defer.inlineCallbacks
    def get_push_action_users_in_range(self, min_stream_ordering, max_stream_ordering):
        def f(txn):
            sql = (
                "SELECT DISTINCT(user_id) FROM event_push_actions WHERE"
                " stream_ordering >= ? AND stream_ordering <= ?"
            )
            txn.execute(sql, (min_stream_ordering, max_stream_ordering))
            return [r[0] for r in txn.fetchall()]
        ret = yield self.runInteraction("get_push_action_users_in_range", f)
        defer.returnValue(ret)

    @defer.inlineCallbacks
    def get_unread_push_actions_for_user_in_range(self, user_id,
                                                  min_stream_ordering,
                                                  max_stream_ordering=None):
        def get_after_receipt(txn):
            sql = (
                "SELECT ep.event_id, ep.room_id, ep.stream_ordering, ep.actions, "
                "e.received_ts "
                "FROM event_push_actions AS ep, ("
                "   SELECT room_id, user_id, "
                "       max(topological_ordering) as topological_ordering, "
                "       max(stream_ordering) as stream_ordering "
                "       FROM events"
                "   NATURAL JOIN receipts_linearized WHERE receipt_type = 'm.read'"
                "   GROUP BY room_id, user_id"
                ") AS rl "
                "NATURAL JOIN events e "
                "WHERE"
                "   ep.room_id = rl.room_id"
                "   AND ("
                "       ep.topological_ordering > rl.topological_ordering"
                "       OR ("
                "           ep.topological_ordering = rl.topological_ordering"
                "           AND ep.stream_ordering > rl.stream_ordering"
                "       )"
                "   )"
                "   AND ep.stream_ordering > ?"
                "   AND ep.user_id = ?"
                "   AND ep.user_id = rl.user_id"
            )
            args = [min_stream_ordering, user_id]
            if max_stream_ordering is not None:
                sql += " AND ep.stream_ordering <= ?"
                args.append(max_stream_ordering)
            sql += " ORDER BY ep.stream_ordering ASC"
            txn.execute(sql, args)
            return txn.fetchall()
        after_read_receipt = yield self.runInteraction(
            "get_unread_push_actions_for_user_in_range", get_after_receipt
        )

        def get_no_receipt(txn):
            sql = (
                "SELECT ep.event_id, ep.room_id, ep.stream_ordering, ep.actions,"
                " e.received_ts"
                " FROM event_push_actions AS ep"
                " JOIN events e ON ep.room_id = e.room_id AND ep.event_id = e.event_id"
                " WHERE ep.room_id not in ("
                "   SELECT room_id FROM events NATURAL JOIN receipts_linearized"
                "   WHERE receipt_type = 'm.read' AND user_id = ?"
                "   GROUP BY room_id"
                ") AND ep.user_id = ? AND ep.stream_ordering > ?"
            )
            args = [user_id, user_id, min_stream_ordering]
            if max_stream_ordering is not None:
                sql += " AND ep.stream_ordering <= ?"
                args.append(max_stream_ordering)
            sql += " ORDER BY ep.stream_ordering ASC"
            txn.execute(sql, args)
            return txn.fetchall()
        no_read_receipt = yield self.runInteraction(
            "get_unread_push_actions_for_user_in_range", get_no_receipt
        )

        defer.returnValue([
            {
                "event_id": row[0],
                "room_id": row[1],
                "stream_ordering": row[2],
                "actions": json.loads(row[3]),
                "received_ts": row[4],
            } for row in after_read_receipt + no_read_receipt
        ])

    @defer.inlineCallbacks
    def get_time_of_last_push_action_before(self, stream_ordering):
        def f(txn):
            sql = (
                "SELECT e.received_ts"
                " FROM event_push_actions AS ep"
                " JOIN events e ON ep.room_id = e.room_id AND ep.event_id = e.event_id"
                " WHERE ep.stream_ordering > ?"
                " ORDER BY ep.stream_ordering ASC"
                " LIMIT 1"
            )
            txn.execute(sql, (stream_ordering,))
            return txn.fetchone()
        result = yield self.runInteraction("get_time_of_last_push_action_before", f)
        defer.returnValue(result[0] if result else None)

    @defer.inlineCallbacks
    def get_latest_push_action_stream_ordering(self):
        def f(txn):
            txn.execute("SELECT MAX(stream_ordering) FROM event_push_actions")
            return txn.fetchone()
        result = yield self.runInteraction(
            "get_latest_push_action_stream_ordering", f
        )
        defer.returnValue(result[0] or 0)

    @defer.inlineCallbacks
    def get_time_of_latest_push_action_by_room_for_user(self, user_id):
        """
        Returns only the received_ts of the last notification in each of the
        user's rooms, in a dict by room_id
        """
        def f(txn):
            txn.execute(
                "SELECT ep.room_id, MAX(e.received_ts)"
                " FROM event_push_actions AS ep"
                " JOIN events e ON ep.room_id = e.room_id AND ep.event_id = e.event_id"
                " WHERE ep.user_id = ?"
                " GROUP BY ep.room_id",
                (user_id,)
            )
            return txn.fetchall()
        result = yield self.runInteraction(
            "get_time_of_latest_push_action_by_room_for_user", f
        )

        defer.returnValue({row[0]: row[1] for row in result})

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
