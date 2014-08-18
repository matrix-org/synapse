# -*- coding: utf-8 -*-
# Copyright 2014 matrix.org
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

from ._base import SQLBaseStore

from synapse.api.constants import Membership

import json
import logging


logger = logging.getLogger(__name__)


MAX_STREAM_SIZE = 1000


class StreamStore(SQLBaseStore):

    @defer.inlineCallbacks
    def get_room_events_stream(self, user_id, from_key, to_key, room_id,
                               limit=0, with_feedback=False):
        # TODO (erikj): Handle compressed feedback

        current_room_membership_sql = (
            "SELECT m.room_id FROM room_memberships as m "
            "INNER JOIN current_state_events as c ON m.event_id = c.event_id "
            "WHERE m.user_id = ?"
        )

        invites_sql = (
            "SELECT m.event_id FROM room_memberships as m "
            "INNER JOIN current_state_events as c ON m.event_id = c.event_id "
            "WHERE m.user_id = ? AND m.membership = ?"
        )

        if limit:
            limit = max(limit, MAX_STREAM_SIZE)
        else:
            limit = MAX_STREAM_SIZE

        # From and to keys should be integers from ordering.
        from_key = int(from_key)
        to_key = int(to_key)

        if from_key == to_key:
            defer.returnValue(([], to_key))
            return

        sql = (
            "SELECT * FROM events as e WHERE "
            "((room_id IN (%(current)s)) OR "
            "(event_id IN (%(invites)s))) "
        ) % {
            "current": current_room_membership_sql,
            "invites": invites_sql,
        }

        # Constraints and ordering depend on direction.
        if from_key < to_key:
            sql += (
                "AND e.token_ordering > ? AND e.token_ordering < ? "
                "ORDER BY token_ordering, rowid ASC LIMIT %(limit)d "
            ) % {"limit": limit}
        else:
            sql += (
                "AND e.token_ordering < ? "
                "AND e.token_ordering > ? "
                "ORDER BY e.token_ordering, rowid DESC LIMIT %(limit)d "
            ) % {"limit": int(limit)}

        rows = yield self._execute_and_decode(
            sql,
            user_id, user_id, Membership.INVITE, from_key, to_key
        )

        ret = [self._parse_event_from_row(r) for r in rows]

        if rows:
            if from_key < to_key:
                key = max([r["token_ordering"] for r in rows])
            else:
                key = min([r["token_ordering"] for r in rows])
        else:
            key = to_key

        defer.returnValue((ret, key))

    @defer.inlineCallbacks
    def get_recent_events_for_room(self, room_id, limit, with_feedback=False):
        # TODO (erikj): Handle compressed feedback

        sql = (
            "SELECT * FROM events WHERE room_id = ? "
            "ORDER BY token_ordering, rowid DESC LIMIT ? "
        )

        rows = yield self._execute_and_decode(
            sql,
            room_id, limit
        )

        rows.reverse()  # As we selected with reverse ordering

        defer.returnValue([self._parse_event_from_row(r) for r in rows])

    @defer.inlineCallbacks
    def get_room_events_max_id(self):
        res = yield self._execute_and_decode(
            "SELECT MAX(token_ordering) as m FROM events"
        )

        if not res:
            defer.returnValue(0)
            return

        defer.returnValue(res[0]["m"])
