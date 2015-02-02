# -*- coding: utf-8 -*-
# Copyright 2014, 2015 OpenMarket Ltd
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

from collections import namedtuple

import logging


logger = logging.getLogger(__name__)


MAX_STREAM_SIZE = 1000


_STREAM_TOKEN = "stream"
_TOPOLOGICAL_TOKEN = "topological"


class _StreamToken(namedtuple("_StreamToken", "topological stream")):
    """Tokens are positions between events. The token "s1" comes after event 1.

            s0    s1
            |     |
        [0] V [1] V [2]

    Tokens can either be a point in the live event stream or a cursor going
    through historic events.

    When traversing the live event stream events are ordered by when they
    arrived at the homeserver.

    When traversing historic events the events are ordered by their depth in
    the event graph "topological_ordering" and then by when they arrived at the
    homeserver "stream_ordering".

    Live tokens start with an "s" followed by the "stream_ordering" id of the
    event it comes after. Historic tokens start with a "t" followed by the
    "topological_ordering" id of the event it comes after, follewed by "-",
    followed by the "stream_ordering" id of the event it comes after.
    """
    __slots__ = []

    @classmethod
    def parse(cls, string):
        try:
            if string[0] == 's':
                return cls(topological=None, stream=int(string[1:]))
            if string[0] == 't':
                parts = string[1:].split('-', 1)
                return cls(topological=int(parts[0]), stream=int(parts[1]))
        except:
            pass
        raise SynapseError(400, "Invalid token %r" % (string,))

    @classmethod
    def parse_stream_token(cls, string):
        try:
            if string[0] == 's':
                return cls(topological=None, stream=int(string[1:]))
        except:
            pass
        raise SynapseError(400, "Invalid token %r" % (string,))

    def __str__(self):
        if self.topological is not None:
            return "t%d-%d" % (self.topological, self.stream)
        else:
            return "s%d" % (self.stream,)

    def lower_bound(self):
        if self.topological is None:
            return "(%d < %s)" % (self.stream, "stream_ordering")
        else:
            return "(%d < %s OR (%d == %s AND %d < %s))" % (
                self.topological, "topological_ordering",
                self.topological, "topological_ordering",
                self.stream, "stream_ordering",
            )

    def upper_bound(self):
        if self.topological is None:
            return "(%d >= %s)" % (self.stream, "stream_ordering")
        else:
            return "(%d > %s OR (%d == %s AND %d >= %s))" % (
                self.topological, "topological_ordering",
                self.topological, "topological_ordering",
                self.stream, "stream_ordering",
            )


class StreamStore(SQLBaseStore):
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

        if limit:
            limit = max(limit, MAX_STREAM_SIZE)
        else:
            limit = MAX_STREAM_SIZE

        # From and to keys should be integers from ordering.
        from_id = _StreamToken.parse_stream_token(from_key)
        to_id = _StreamToken.parse_stream_token(to_key)

        if from_key == to_key:
            return defer.succeed(([], to_key))

        sql = (
            "SELECT e.event_id, e.stream_ordering FROM events AS e WHERE "
            "(e.outlier = 0 AND (room_id IN (%(current)s)) OR "
            "(event_id IN (%(invites)s))) "
            "AND e.stream_ordering > ? AND e.stream_ordering <= ? "
            "ORDER BY stream_ordering ASC LIMIT %(limit)d "
        ) % {
            "current": current_room_membership_sql,
            "invites": membership_sql,
            "limit": limit
        }

        def f(txn):
            txn.execute(sql, (user_id, user_id, from_id.stream, to_id.stream,))

            rows = self.cursor_to_dict(txn)

            ret = self._get_events_txn(
                txn,
                [r["event_id"] for r in rows],
                get_prev_content=True
            )

            self._set_before_and_after(ret, rows)

            if rows:
                key = "s%d" % max([r["stream_ordering"] for r in rows])

            else:
                # Assume we didn't get anything because there was nothing to
                # get.
                key = to_key

            return ret, key

        return self.runInteraction("get_room_events_stream", f)

    @log_function
    def paginate_room_events(self, room_id, from_key, to_key=None,
                             direction='b', limit=-1,
                             with_feedback=False):
        # TODO (erikj): Handle compressed feedback

        # Tokens really represent positions between elements, but we use
        # the convention of pointing to the event before the gap. Hence
        # we have a bit of asymmetry when it comes to equalities.
        args = [room_id]
        if direction == 'b':
            order = "DESC"
            bounds = _StreamToken.parse(from_key).upper_bound()
            if to_key:
                bounds = "%s AND %s" % (
                    bounds, _StreamToken.parse(to_key).lower_bound()
                )
        else:
            order = "ASC"
            bounds = _StreamToken.parse(from_key).lower_bound()
            if to_key:
                bounds = "%s AND %s" % (
                    bounds, _StreamToken.parse(to_key).upper_bound()
                )

        if int(limit) > 0:
            args.append(int(limit))
            limit_str = " LIMIT ?"
        else:
            limit_str = ""

        sql = (
            "SELECT * FROM events"
            " WHERE outlier = 0 AND room_id = ? AND %(bounds)s"
            " ORDER BY topological_ordering %(order)s,"
            " stream_ordering %(order)s %(limit)s"
        ) % {
            "bounds": bounds,
            "order": order,
            "limit": limit_str
        }

        def f(txn):
            txn.execute(sql, args)

            rows = self.cursor_to_dict(txn)

            if rows:
                topo = rows[-1]["topological_ordering"]
                toke = rows[-1]["stream_ordering"]
                if direction == 'b':
                    # Tokens are positions between events.
                    # This token points *after* the last event in the chunk.
                    # We need it to point to the event before it in the chunk
                    # when we are going backwards so we subtract one from the
                    # stream part.
                    toke -= 1
                next_token = str(_StreamToken(topo, toke))
            else:
                # TODO (erikj): We should work out what to do here instead.
                next_token = to_key if to_key else from_key

            events = self._get_events_txn(
                txn,
                [r["event_id"] for r in rows],
                get_prev_content=True
            )

            self._set_before_and_after(events, rows)

            return events, next_token,

        return self.runInteraction("paginate_room_events", f)

    def get_recent_events_for_room(self, room_id, limit, end_token,
                                   with_feedback=False, from_token=None):
        # TODO (erikj): Handle compressed feedback

        end_token = _StreamToken.parse_stream_token(end_token)

        if from_token is None:
            sql = (
                "SELECT stream_ordering, topological_ordering, event_id"
                " FROM events"
                " WHERE room_id = ? AND stream_ordering <= ? AND outlier = 0"
                " ORDER BY topological_ordering DESC, stream_ordering DESC"
                " LIMIT ?"
            )
        else:
            from_token = _StreamToken.parse_stream_token(from_token)
            sql = (
                "SELECT stream_ordering, topological_ordering, event_id"
                " FROM events"
                " WHERE room_id = ? AND stream_ordering > ?"
                " AND stream_ordering <= ? AND outlier = 0"
                " ORDER BY topological_ordering DESC, stream_ordering DESC"
                " LIMIT ?"
            )

        def get_recent_events_for_room_txn(txn):
            if from_token is None:
                txn.execute(sql, (room_id, end_token.stream, limit,))
            else:
                txn.execute(sql, (
                    room_id, from_token.stream, end_token.stream, limit
                ))

            rows = self.cursor_to_dict(txn)

            rows.reverse()  # As we selected with reverse ordering

            if rows:
                # Tokens are positions between events.
                # This token points *after* the last event in the chunk.
                # We need it to point to the event before it in the chunk
                # since we are going backwards so we subtract one from the
                # stream part.
                topo = rows[0]["topological_ordering"]
                toke = rows[0]["stream_ordering"] - 1
                start_token = str(_StreamToken(topo, toke))

                token = (start_token, str(end_token))
            else:
                token = (str(end_token), str(end_token))

            events = self._get_events_txn(
                txn,
                [r["event_id"] for r in rows],
                get_prev_content=True
            )

            self._set_before_and_after(events, rows)

            return events, token

        return self.runInteraction(
            "get_recent_events_for_room", get_recent_events_for_room_txn
        )

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

    @staticmethod
    def _set_before_and_after(events, rows):
        for event, row in zip(events, rows):
            stream = row["stream_ordering"]
            topo = event.depth
            internal = event.internal_metadata
            internal.before = str(_StreamToken(topo, stream - 1))
            internal.after = str(_StreamToken(topo, stream))
