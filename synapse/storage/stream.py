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

""" This module is responsible for getting events from the DB for pagination
and event streaming.

The order it returns events in depend on whether we are streaming forwards or
are paginating backwards. We do this because we want to handle out of order
messages nicely, while still returning them in the correct order when we
paginate bacwards.

This is implemented by keeping two ordering columns: stream_ordering and
topological_ordering. Stream ordering is basically insertion/received order
(except for events from backfill requests). The topolgical_ordering is a
weak ordering of events based on the pdu graph.

This means that we have to have two different types of tokens, depending on
what sort order was used:
    - stream tokens are of the form: "s%d", which maps directly to the column
    - topological tokems: "t%d-%d", where the integers map to the topological
      and stream ordering columns respectively.
"""

from twisted.internet import defer

from ._base import SQLBaseStore
from synapse.api.errors import SynapseError
from synapse.util.logutils import log_function

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
        raise SynapseError(400, "Invalid token")


def _parse_topological_token(string):
    try:
        if string[0] != 't':
            raise
        parts = string[1:].split('-', 1)
        return (int(parts[0]), int(parts[1]))
    except:
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
        # We deal with events request in two different ways depending on if
        # this looks like an /events request or a pagination request.
        is_events = (
            direction == 'f'
            and user_id
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
            "WHERE m.user_id = ? AND m.membership = 'join'"
        )

        # We also want to get any membership events about that user, e.g.
        # invites or leave notifications.
        membership_sql = (
            "SELECT m.event_id FROM room_memberships as m "
            "INNER JOIN current_state_events as c ON m.event_id = c.event_id "
            "WHERE m.user_id = ? "
        )

        del_sql = (
            "SELECT event_id FROM redactions WHERE redacts = e.event_id "
            "LIMIT 1"
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
            "SELECT *, (%(redacted)s) AS redacted FROM events AS e WHERE "
            "(e.outlier = 0 AND (room_id IN (%(current)s)) OR "
            "(event_id IN (%(invites)s))) "
            "AND e.stream_ordering > ? AND e.stream_ordering <= ? "
            "ORDER BY stream_ordering ASC LIMIT %(limit)d "
        ) % {
            "redacted": del_sql,
            "current": current_room_membership_sql,
            "invites": membership_sql,
            "limit": limit
        }

        rows = yield self._execute_and_decode(
            sql,
            user_id, user_id, from_id, to_id
        )

        ret = yield self._parse_events(rows)

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

        # Tokens really represent positions between elements, but we use
        # the convention of pointing to the event before the gap. Hence
        # we have a bit of asymmetry when it comes to equalities.
        from_comp = '<=' if direction == 'b' else '>'
        to_comp = '>' if direction == 'b' else '<='
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

        del_sql = (
            "SELECT event_id FROM redactions WHERE redacts = events.event_id "
            "LIMIT 1"
        )

        sql = (
            "SELECT *, (%(redacted)s) AS redacted FROM events"
            " WHERE outlier = 0 AND room_id = ? AND %(bounds)s"
            " ORDER BY topological_ordering %(order)s,"
            " stream_ordering %(order)s %(limit)s"
        ) % {
            "redacted": del_sql,
            "bounds": bounds,
            "order": order,
            "limit": limit_str
        }

        rows = yield self._execute_and_decode(
            sql,
            *args
        )

        if rows:
            topo = rows[-1]["topological_ordering"]
            toke = rows[-1]["stream_ordering"]
            if direction == 'b':
                topo -= 1
                toke -= 1
            next_token = "t%s-%s" % (topo, toke)
        else:
            # TODO (erikj): We should work out what to do here instead.
            next_token = to_key if to_key else from_key

        events = yield self._parse_events(rows)

        defer.returnValue(
            (
                events,
                next_token
            )
        )

    @defer.inlineCallbacks
    def get_recent_events_for_room(self, room_id, limit, end_token,
                                   with_feedback=False):
        # TODO (erikj): Handle compressed feedback

        del_sql = (
            "SELECT event_id FROM redactions WHERE redacts = events.event_id "
            "LIMIT 1"
        )

        sql = (
            "SELECT *, (%(redacted)s) AS redacted FROM events "
            "WHERE room_id = ? AND stream_ordering <= ? AND outlier = 0 "
            "ORDER BY topological_ordering DESC, stream_ordering DESC LIMIT ? "
        ) % {
            "redacted": del_sql,
        }

        rows = yield self._execute_and_decode(
            sql,
            room_id, end_token, limit
        )

        rows.reverse()  # As we selected with reverse ordering

        if rows:
            topo = rows[0]["topological_ordering"]
            toke = rows[0]["stream_ordering"]
            start_token = "t%s-%s" % (topo, toke)

            token = (start_token, end_token)
        else:
            token = (end_token, end_token)

        events = yield self._parse_events(rows)

        ret = (events, token)

        defer.returnValue(ret)

    def get_room_events_max_id(self):
        return self.runInteraction(
            "get_room_events_max_id",
            self._get_room_events_max_id_txn
        )

    def _get_room_events_max_id_txn(self, txn):
        txn.execute(
            "SELECT MAX(stream_ordering) as m FROM events"
        )

        res = self.cursor_to_dict(txn)

        logger.debug("get_room_events_max_id: %s", res)

        if not res or not res[0] or not res[0]["m"]:
            return "s0"

        key = res[0]["m"]
        return "s%d" % (key,)
