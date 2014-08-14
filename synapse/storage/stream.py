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


from ._base import SQLBaseStore
from .message import MessagesTable
from .feedback import FeedbackTable
from .roomdata import RoomDataTable
from .roommember import RoomMemberTable

from synapse.api.constants import Membership

import json
import logging


logger = logging.getLogger(__name__)


MAX_STREAM_SIZE = 1000


class StreamStore(SQLBaseStore):

    @defer.inlineCallbacks
    def get_room_events_stream(self, user_id, from_key, to_key, room_id,
                               limit=0, with_feedback=False):

        current_room_membership_sql = (
            "SELECT m.room_id FROM room_memberships as m "
            "INNER JOIN current_state as c ON m.event_id = c.event_id "
            "WHERE m.user_id = ?"
        )

        invites_sql = (
            "SELECT m.event_id FROM room_membershipas as m "
            "INNER JOIN current_state as c ON m.event_id = c.event_id "
            "WHERE m.user_id = ? AND m.membership = ?"
        )

        if limit:
            limit = max(limit, MAX_STREAM_SIZE)
        else:
            limit = 1000

        sql = (
            "SELECT * FROM events as e WHERE "
            "(room_id IN (%(current)s)) OR "
            "(event_id IN (%(invites)s)) "
            "ORDER BY ordering ASC LIMIT %(limit)d"
        ) % {
            "current": current_room_membership_sql,
            "invites": invites_sql,
            "limit": limit,
        }

        rows = yield self._execute_and_decode(
            sql,
            user_id, user_id, Membership.INVITE
        )

        defer.returnValue([self._parse_event_from_row(r) for r in results])
