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
from synapse.api.errors import SynapseError
from synapse.api.constants import Membership
from synapse.util.logutils import log_function

import json
import logging


logger = logging.getLogger(__name__)


MAX_STREAM_SIZE = 1000


_STREAM_TOKEN = "stream"
_TOPOLOGICAL_TOKEN = "topological"


def _parse_stream_token(string):
    try:
        if string[0] != 's':
            raise
        return int(string[1:])
    except:
        logger.debug("Not stream token: %s", string)
        raise SynapseError(400, "Invalid token")


def _parse_topological_token(string):
    try:
        if string[0] != 't':
            raise
        parts = string[1:].split('-', 1)
        return (int(parts[0]), int(parts[1]))
    except:
        logger.debug("Not topological token: %s", string)
        raise SynapseError(400, "Invalid token")


def is_stream_token(string):
    try:
        _parse_stream_token(string)
        return True
    except:
        return False


def is_topological_token(string):
    try:
        _parse_topological_token(string)
        return True
    except:
        return False


def _get_token_bound(token, comparison):
    try:
        s = _parse_stream_token(token)
        return "%s %s %d" % ("stream_ordering", comparison, s)
    except:
        pass

    try:
        top, stream = _parse_topological_token(token)
        return "%s %s %d AND %s %s %d" % (
            "topological_ordering", comparison, top,
            "stream_ordering", comparison, stream,
        )
    except:
        pass

    raise SynapseError(400, "Invalid token")


class StreamStore(SQLBaseStore):
    @log_function
    def get_room_events(self, user_id, from_key, to_key, room_id, limit=0,
                        direction='f', with_feedback=False):
        is_events = (
            direction == 'f'
            and is_stream_token(from_key)
            and to_key and is_stream_token(to_key)
        )

        if is_events:
            return self.get_room_events_stream(
                user_id=user_id,
                from_key=from_key,
                to_key=to_key,
                room_id=room_id,
                limit=limit,
                with_feedback=with_feedback,
            )
        else:
            return self.paginate_room_events(
                from_key=from_key,
                to_key=to_key,
                room_id=room_id,
                limit=limit,
                with_feedback=with_feedback,
            )

    @defer.inlineCallbacks
    @log_function
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
        from_id = _parse_stream_token(from_key)
        to_id = _parse_stream_token(to_key)

        if from_key == to_key:
            defer.returnValue(([], to_key))
            return

        sql = (
            "SELECT * FROM events as e WHERE "
            "((room_id IN (%(current)s)) OR "
            "(event_id IN (%(invites)s))) "
            "AND e.stream_ordering > ? AND e.stream_ordering < ? "
            "ORDER BY stream_ordering ASC LIMIT %(limit)d "
        ) % {
            "current": current_room_membership_sql,
            "invites": invites_sql,
            "limit": limit
        }

        rows = yield self._execute_and_decode(
            sql,
            user_id, user_id, Membership.INVITE, from_id, to_id
        )

        ret = [self._parse_event_from_row(r) for r in rows]

        if rows:
            key = "s%d" % max([r["stream_ordering"] for r in rows])
        else:
            # Assume we didn't get anything because there was nothing to get.
            key = to_key

        defer.returnValue((ret, key))

    @defer.inlineCallbacks
    @log_function
    def paginate_room_events(self, room_id, from_key, to_key=None,
                             direction='b', limit=-1,
                             with_feedback=False):
        # TODO (erikj): Handle compressed feedback

        from_comp = '<' if direction =='b' else '>'
        to_comp = '>' if direction =='b' else '<'
        order = "DESC" if direction == 'b' else "ASC"

        args = [room_id]

        bounds = _get_token_bound(from_key, from_comp)
        if to_key:
            bounds = "%s AND %s" % (bounds, _get_token_bound(to_key, to_comp))

        if int(limit) > 0:
            args.append(int(limit))
            limit_str = " LIMIT ?"
        else:
            limit_str = ""

        sql = (
            "SELECT * FROM events "
            "WHERE room_id = ? AND %(bounds)s "
            "ORDER BY topological_ordering %(order)s, stream_ordering %(order)s %(limit)s "
        ) % {"bounds": bounds, "order": order, "limit": limit_str}

        rows = yield self._execute_and_decode(
            sql,
            *args
        )

        if rows:
            topo = rows[-1]["topological_ordering"]
            toke = rows[-1]["stream_ordering"]
            next_token = "t%s-%s" % (topo, toke)
        else:
            # TODO (erikj): We should work out what to do here instead.
            next_token = to_key if to_key else from_key

        defer.returnValue(
            (
                [self._parse_event_from_row(r) for r in rows],
                next_token
            )
        )

    @defer.inlineCallbacks
    def get_recent_events_for_room(self, room_id, limit, with_feedback=False):
        # TODO (erikj): Handle compressed feedback

        end_token = yield self.get_room_events_max_id()

        sql = (
            "SELECT * FROM events "
            "WHERE room_id = ? AND stream_ordering <= ? "
            "ORDER BY topological_ordering, stream_ordering DESC LIMIT ? "
        )

        rows = yield self._execute_and_decode(
            sql,
            room_id, end_token, limit
        )

        rows.reverse()  # As we selected with reverse ordering

        if rows:
            topo = rows[0]["topological_ordering"]
            toke = rows[0]["stream_ordering"]
            start_token = "p%s-%s" % (topo, toke)

            token = (start_token, end_token)
        else:
            token = (end_token, end_token)

        defer.returnValue(
            (
                [self._parse_event_from_row(r) for r in rows],
                token
            )
        )

    @defer.inlineCallbacks
    def get_room_events_max_id(self):
        res = yield self._execute_and_decode(
            "SELECT MAX(stream_ordering) as m FROM events"
        )

        logger.debug("get_room_events_max_id: %s", res)

        if not res or not res[0] or not res[0]["m"]:
            defer.returnValue("s1")
            return

        key = res[0]["m"] + 1
        defer.returnValue("s%d" % (key,))
