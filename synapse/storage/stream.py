# -*- coding: utf-8 -*-
# Copyright 2014-2016 OpenMarket Ltd
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
(except for events from backfill requests). The topological_ordering is a
weak ordering of events based on the pdu graph.

This means that we have to have two different types of tokens, depending on
what sort order was used:
    - stream tokens are of the form: "s%d", which maps directly to the column
    - topological tokems: "t%d-%d", where the integers map to the topological
      and stream ordering columns respectively.
"""

from twisted.internet import defer

from ._base import SQLBaseStore
from synapse.util.caches.descriptors import cached
from synapse.api.constants import EventTypes
from synapse.types import RoomStreamToken
from synapse.util.logcontext import preserve_fn, preserve_context_over_deferred
from synapse.storage.engines import PostgresEngine, Sqlite3Engine

import logging


logger = logging.getLogger(__name__)


MAX_STREAM_SIZE = 1000


_STREAM_TOKEN = "stream"
_TOPOLOGICAL_TOKEN = "topological"


def lower_bound(token, engine, inclusive=False):
    inclusive = "=" if inclusive else ""
    if token.topological is None:
        return "(%d <%s %s)" % (token.stream, inclusive, "stream_ordering")
    else:
        if isinstance(engine, PostgresEngine):
            # Postgres doesn't optimise ``(x < a) OR (x=a AND y<b)`` as well
            # as it optimises ``(x,y) < (a,b)`` on multicolumn indexes. So we
            # use the later form when running against postgres.
            return "((%d,%d) <%s (%s,%s))" % (
                token.topological, token.stream, inclusive,
                "topological_ordering", "stream_ordering",
            )
        return "(%d < %s OR (%d = %s AND %d <%s %s))" % (
            token.topological, "topological_ordering",
            token.topological, "topological_ordering",
            token.stream, inclusive, "stream_ordering",
        )


def upper_bound(token, engine, inclusive=True):
    inclusive = "=" if inclusive else ""
    if token.topological is None:
        return "(%d >%s %s)" % (token.stream, inclusive, "stream_ordering")
    else:
        if isinstance(engine, PostgresEngine):
            # Postgres doesn't optimise ``(x > a) OR (x=a AND y>b)`` as well
            # as it optimises ``(x,y) > (a,b)`` on multicolumn indexes. So we
            # use the later form when running against postgres.
            return "((%d,%d) >%s (%s,%s))" % (
                token.topological, token.stream, inclusive,
                "topological_ordering", "stream_ordering",
            )
        return "(%d > %s OR (%d = %s AND %d >%s %s))" % (
            token.topological, "topological_ordering",
            token.topological, "topological_ordering",
            token.stream, inclusive, "stream_ordering",
        )


def filter_to_clause(event_filter):
    # NB: This may create SQL clauses that don't optimise well (and we don't
    # have indices on all possible clauses). E.g. it may create
    # "room_id == X AND room_id != X", which postgres doesn't optimise.

    if not event_filter:
        return "", []

    clauses = []
    args = []

    if event_filter.types:
        clauses.append(
            "(%s)" % " OR ".join("type = ?" for _ in event_filter.types)
        )
        args.extend(event_filter.types)

    for typ in event_filter.not_types:
        clauses.append("type != ?")
        args.append(typ)

    if event_filter.senders:
        clauses.append(
            "(%s)" % " OR ".join("sender = ?" for _ in event_filter.senders)
        )
        args.extend(event_filter.senders)

    for sender in event_filter.not_senders:
        clauses.append("sender != ?")
        args.append(sender)

    if event_filter.rooms:
        clauses.append(
            "(%s)" % " OR ".join("room_id = ?" for _ in event_filter.rooms)
        )
        args.extend(event_filter.rooms)

    for room_id in event_filter.not_rooms:
        clauses.append("room_id != ?")
        args.append(room_id)

    if event_filter.contains_url:
        clauses.append("contains_url = ?")
        args.append(event_filter.contains_url)

    return " AND ".join(clauses), args


class StreamStore(SQLBaseStore):
    @defer.inlineCallbacks
    def get_appservice_room_stream(self, service, from_key, to_key, limit=0):
        # NB this lives here instead of appservice.py so we can reuse the
        # 'private' StreamToken class in this file.
        if limit:
            limit = max(limit, MAX_STREAM_SIZE)
        else:
            limit = MAX_STREAM_SIZE

        # From and to keys should be integers from ordering.
        from_id = RoomStreamToken.parse_stream_token(from_key)
        to_id = RoomStreamToken.parse_stream_token(to_key)

        if from_key == to_key:
            defer.returnValue(([], to_key))
            return

        # select all the events between from/to with a sensible limit
        sql = (
            "SELECT e.event_id, e.room_id, e.type, s.state_key, "
            "e.stream_ordering FROM events AS e "
            "LEFT JOIN state_events as s ON "
            "e.event_id = s.event_id "
            "WHERE e.stream_ordering > ? AND e.stream_ordering <= ? "
            "ORDER BY stream_ordering ASC LIMIT %(limit)d "
        ) % {
            "limit": limit
        }

        def f(txn):
            # pull out all the events between the tokens
            txn.execute(sql, (from_id.stream, to_id.stream,))
            rows = self.cursor_to_dict(txn)

            # Logic:
            #  - We want ALL events which match the AS room_id regex
            #  - We want ALL events which match the rooms represented by the AS
            #    room_alias regex
            #  - We want ALL events for rooms that AS users have joined.
            # This is currently supported via get_app_service_rooms (which is
            # used for the Notifier listener rooms). We can't reasonably make a
            # SQL query for these room IDs, so we'll pull all the events between
            # from/to and filter in python.
            rooms_for_as = self._get_app_service_rooms_txn(txn, service)
            room_ids_for_as = [r.room_id for r in rooms_for_as]

            def app_service_interested(row):
                if row["room_id"] in room_ids_for_as:
                    return True

                if row["type"] == EventTypes.Member:
                    if service.is_interested_in_user(row.get("state_key")):
                        return True
                return False

            return [r for r in rows if app_service_interested(r)]

        rows = yield self.runInteraction("get_appservice_room_stream", f)

        ret = yield self._get_events(
            [r["event_id"] for r in rows],
            get_prev_content=True
        )

        self._set_before_and_after(ret, rows, topo_order=from_id is None)

        if rows:
            key = "s%d" % max(r["stream_ordering"] for r in rows)
        else:
            # Assume we didn't get anything because there was nothing to
            # get.
            key = to_key

        defer.returnValue((ret, key))

    @defer.inlineCallbacks
    def get_room_events_stream_for_rooms(self, room_ids, from_key, to_key, limit=0,
                                         order='DESC'):
        from_id = RoomStreamToken.parse_stream_token(from_key).stream

        room_ids = yield self._events_stream_cache.get_entities_changed(
            room_ids, from_id
        )

        if not room_ids:
            defer.returnValue({})

        results = {}
        room_ids = list(room_ids)
        for rm_ids in (room_ids[i:i + 20] for i in xrange(0, len(room_ids), 20)):
            res = yield preserve_context_over_deferred(defer.gatherResults([
                preserve_fn(self.get_room_events_stream_for_room)(
                    room_id, from_key, to_key, limit, order=order,
                )
                for room_id in rm_ids
            ]))
            results.update(dict(zip(rm_ids, res)))

        defer.returnValue(results)

    def get_rooms_that_changed(self, room_ids, from_key):
        """Given a list of rooms and a token, return rooms where there may have
        been changes.

        Args:
            room_ids (list)
            from_key (str): The room_key portion of a StreamToken
        """
        from_key = RoomStreamToken.parse_stream_token(from_key).stream
        return set(
            room_id for room_id in room_ids
            if self._events_stream_cache.has_entity_changed(room_id, from_key)
        )

    @defer.inlineCallbacks
    def get_room_events_stream_for_room(self, room_id, from_key, to_key, limit=0,
                                        order='DESC'):
        # Note: If from_key is None then we return in topological order. This
        # is because in that case we're using this as a "get the last few messages
        # in a room" function, rather than "get new messages since last sync"
        if from_key is not None:
            from_id = RoomStreamToken.parse_stream_token(from_key).stream
        else:
            from_id = None
        to_id = RoomStreamToken.parse_stream_token(to_key).stream

        if from_key == to_key:
            defer.returnValue(([], from_key))

        if from_id:
            has_changed = yield self._events_stream_cache.has_entity_changed(
                room_id, from_id
            )

            if not has_changed:
                defer.returnValue(([], from_key))

        def f(txn):
            if from_id is not None:
                sql = (
                    "SELECT event_id, stream_ordering FROM events WHERE"
                    " room_id = ?"
                    " AND not outlier"
                    " AND stream_ordering > ? AND stream_ordering <= ?"
                    " ORDER BY stream_ordering %s LIMIT ?"
                ) % (order,)
                txn.execute(sql, (room_id, from_id, to_id, limit))
            else:
                sql = (
                    "SELECT event_id, stream_ordering FROM events WHERE"
                    " room_id = ?"
                    " AND not outlier"
                    " AND stream_ordering <= ?"
                    " ORDER BY topological_ordering %s, stream_ordering %s LIMIT ?"
                ) % (order, order,)
                txn.execute(sql, (room_id, to_id, limit))

            rows = self.cursor_to_dict(txn)

            return rows

        rows = yield self.runInteraction("get_room_events_stream_for_room", f)

        ret = yield self._get_events(
            [r["event_id"] for r in rows],
            get_prev_content=True
        )

        self._set_before_and_after(ret, rows, topo_order=from_id is None)

        if order.lower() == "desc":
            ret.reverse()

        if rows:
            key = "s%d" % min(r["stream_ordering"] for r in rows)
        else:
            # Assume we didn't get anything because there was nothing to
            # get.
            key = from_key

        defer.returnValue((ret, key))

    @defer.inlineCallbacks
    def get_membership_changes_for_user(self, user_id, from_key, to_key):
        if from_key is not None:
            from_id = RoomStreamToken.parse_stream_token(from_key).stream
        else:
            from_id = None
        to_id = RoomStreamToken.parse_stream_token(to_key).stream

        if from_key == to_key:
            defer.returnValue([])

        if from_id:
            has_changed = self._membership_stream_cache.has_entity_changed(
                user_id, int(from_id)
            )
            if not has_changed:
                defer.returnValue([])

        def f(txn):
            if from_id is not None:
                sql = (
                    "SELECT m.event_id, stream_ordering FROM events AS e,"
                    " room_memberships AS m"
                    " WHERE e.event_id = m.event_id"
                    " AND m.user_id = ?"
                    " AND e.stream_ordering > ? AND e.stream_ordering <= ?"
                    " ORDER BY e.stream_ordering ASC"
                )
                txn.execute(sql, (user_id, from_id, to_id,))
            else:
                sql = (
                    "SELECT m.event_id, stream_ordering FROM events AS e,"
                    " room_memberships AS m"
                    " WHERE e.event_id = m.event_id"
                    " AND m.user_id = ?"
                    " AND stream_ordering <= ?"
                    " ORDER BY stream_ordering ASC"
                )
                txn.execute(sql, (user_id, to_id,))
            rows = self.cursor_to_dict(txn)

            return rows

        rows = yield self.runInteraction("get_membership_changes_for_user", f)

        ret = yield self._get_events(
            [r["event_id"] for r in rows],
            get_prev_content=True
        )

        self._set_before_and_after(ret, rows, topo_order=False)

        defer.returnValue(ret)

    @defer.inlineCallbacks
    def paginate_room_events(self, room_id, from_key, to_key=None,
                             direction='b', limit=-1, event_filter=None):
        # Tokens really represent positions between elements, but we use
        # the convention of pointing to the event before the gap. Hence
        # we have a bit of asymmetry when it comes to equalities.
        args = [False, room_id]
        if direction == 'b':
            order = "DESC"
            bounds = upper_bound(
                RoomStreamToken.parse(from_key), self.database_engine
            )
            if to_key:
                bounds = "%s AND %s" % (bounds, lower_bound(
                    RoomStreamToken.parse(to_key), self.database_engine
                ))
        else:
            order = "ASC"
            bounds = lower_bound(
                RoomStreamToken.parse(from_key), self.database_engine
            )
            if to_key:
                bounds = "%s AND %s" % (bounds, upper_bound(
                    RoomStreamToken.parse(to_key), self.database_engine
                ))

        filter_clause, filter_args = filter_to_clause(event_filter)

        if filter_clause:
            bounds += " AND " + filter_clause
            args.extend(filter_args)

        if int(limit) > 0:
            args.append(int(limit))
            limit_str = " LIMIT ?"
        else:
            limit_str = ""

        sql = (
            "SELECT * FROM events"
            " WHERE outlier = ? AND room_id = ? AND %(bounds)s"
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
                next_token = str(RoomStreamToken(topo, toke))
            else:
                # TODO (erikj): We should work out what to do here instead.
                next_token = to_key if to_key else from_key

            return rows, next_token,

        rows, token = yield self.runInteraction("paginate_room_events", f)

        events = yield self._get_events(
            [r["event_id"] for r in rows],
            get_prev_content=True
        )

        self._set_before_and_after(events, rows)

        defer.returnValue((events, token))

    @defer.inlineCallbacks
    def get_recent_events_for_room(self, room_id, limit, end_token, from_token=None):
        rows, token = yield self.get_recent_event_ids_for_room(
            room_id, limit, end_token, from_token
        )

        logger.debug("stream before")
        events = yield self._get_events(
            [r["event_id"] for r in rows],
            get_prev_content=True
        )
        logger.debug("stream after")

        self._set_before_and_after(events, rows)

        defer.returnValue((events, token))

    @cached(num_args=4)
    def get_recent_event_ids_for_room(self, room_id, limit, end_token, from_token=None):
        end_token = RoomStreamToken.parse_stream_token(end_token)

        if from_token is None:
            sql = (
                "SELECT stream_ordering, topological_ordering, event_id"
                " FROM events"
                " WHERE room_id = ? AND stream_ordering <= ? AND outlier = ?"
                " ORDER BY topological_ordering DESC, stream_ordering DESC"
                " LIMIT ?"
            )
        else:
            from_token = RoomStreamToken.parse_stream_token(from_token)
            sql = (
                "SELECT stream_ordering, topological_ordering, event_id"
                " FROM events"
                " WHERE room_id = ? AND stream_ordering > ?"
                " AND stream_ordering <= ? AND outlier = ?"
                " ORDER BY topological_ordering DESC, stream_ordering DESC"
                " LIMIT ?"
            )

        def get_recent_events_for_room_txn(txn):
            if from_token is None:
                txn.execute(sql, (room_id, end_token.stream, False, limit,))
            else:
                txn.execute(sql, (
                    room_id, from_token.stream, end_token.stream, False, limit
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
                start_token = str(RoomStreamToken(topo, toke))

                token = (start_token, str(end_token))
            else:
                token = (str(end_token), str(end_token))

            return rows, token

        return self.runInteraction(
            "get_recent_events_for_room", get_recent_events_for_room_txn
        )

    @defer.inlineCallbacks
    def get_room_events_max_id(self, room_id=None):
        """Returns the current token for rooms stream.

        By default, it returns the current global stream token. Specifying a
        `room_id` causes it to return the current room specific topological
        token.
        """
        token = yield self._stream_id_gen.get_current_token()
        if room_id is None:
            defer.returnValue("s%d" % (token,))
        else:
            topo = yield self.runInteraction(
                "_get_max_topological_txn", self._get_max_topological_txn,
                room_id,
            )
            defer.returnValue("t%d-%d" % (topo, token))

    def get_room_max_stream_ordering(self):
        return self._stream_id_gen.get_current_token()

    def get_room_min_stream_ordering(self):
        return self._backfill_id_gen.get_current_token()

    def get_stream_token_for_event(self, event_id):
        """The stream token for an event
        Args:
            event_id(str): The id of the event to look up a stream token for.
        Raises:
            StoreError if the event wasn't in the database.
        Returns:
            A deferred "s%d" stream token.
        """
        return self._simple_select_one_onecol(
            table="events",
            keyvalues={"event_id": event_id},
            retcol="stream_ordering",
        ).addCallback(lambda row: "s%d" % (row,))

    def get_topological_token_for_event(self, event_id):
        """The stream token for an event
        Args:
            event_id(str): The id of the event to look up a stream token for.
        Raises:
            StoreError if the event wasn't in the database.
        Returns:
            A deferred "t%d-%d" topological token.
        """
        return self._simple_select_one(
            table="events",
            keyvalues={"event_id": event_id},
            retcols=("stream_ordering", "topological_ordering"),
            desc="get_topological_token_for_event",
        ).addCallback(lambda row: "t%d-%d" % (
            row["topological_ordering"], row["stream_ordering"],)
        )

    def get_max_topological_token(self, room_id, stream_key):
        sql = (
            "SELECT max(topological_ordering) FROM events"
            " WHERE room_id = ? AND stream_ordering < ?"
        )
        return self._execute(
            "get_max_topological_token", None,
            sql, room_id, stream_key,
        ).addCallback(
            lambda r: r[0][0] if r else 0
        )

    def _get_max_topological_txn(self, txn, room_id):
        txn.execute(
            "SELECT MAX(topological_ordering) FROM events"
            " WHERE room_id = ?",
            (room_id,)
        )

        rows = txn.fetchall()
        return rows[0][0] if rows else 0

    @staticmethod
    def _set_before_and_after(events, rows, topo_order=True):
        for event, row in zip(events, rows):
            stream = row["stream_ordering"]
            if topo_order:
                topo = event.depth
            else:
                topo = None
            internal = event.internal_metadata
            internal.before = str(RoomStreamToken(topo, stream - 1))
            internal.after = str(RoomStreamToken(topo, stream))
            internal.order = (
                int(topo) if topo else 0,
                int(stream),
            )

    @defer.inlineCallbacks
    def get_events_around(self, room_id, event_id, before_limit, after_limit):
        """Retrieve events and pagination tokens around a given event in a
        room.

        Args:
            room_id (str)
            event_id (str)
            before_limit (int)
            after_limit (int)

        Returns:
            dict
        """

        results = yield self.runInteraction(
            "get_events_around", self._get_events_around_txn,
            room_id, event_id, before_limit, after_limit
        )

        events_before = yield self._get_events(
            [e for e in results["before"]["event_ids"]],
            get_prev_content=True
        )

        events_after = yield self._get_events(
            [e for e in results["after"]["event_ids"]],
            get_prev_content=True
        )

        defer.returnValue({
            "events_before": events_before,
            "events_after": events_after,
            "start": results["before"]["token"],
            "end": results["after"]["token"],
        })

    def _get_events_around_txn(self, txn, room_id, event_id, before_limit, after_limit):
        """Retrieves event_ids and pagination tokens around a given event in a
        room.

        Args:
            room_id (str)
            event_id (str)
            before_limit (int)
            after_limit (int)

        Returns:
            dict
        """

        results = self._simple_select_one_txn(
            txn,
            "events",
            keyvalues={
                "event_id": event_id,
                "room_id": room_id,
            },
            retcols=["stream_ordering", "topological_ordering"],
        )

        token = RoomStreamToken(
            results["topological_ordering"],
            results["stream_ordering"],
        )

        if isinstance(self.database_engine, Sqlite3Engine):
            # SQLite3 doesn't optimise ``(x < a) OR (x = a AND y < b)``
            # So we give pass it to SQLite3 as the UNION ALL of the two queries.

            query_before = (
                "SELECT topological_ordering, stream_ordering, event_id FROM events"
                " WHERE room_id = ? AND topological_ordering < ?"
                " UNION ALL"
                " SELECT topological_ordering, stream_ordering, event_id FROM events"
                " WHERE room_id = ? AND topological_ordering = ? AND stream_ordering < ?"
                " ORDER BY topological_ordering DESC, stream_ordering DESC LIMIT ?"
            )
            before_args = (
                room_id, token.topological,
                room_id, token.topological, token.stream,
                before_limit,
            )

            query_after = (
                "SELECT topological_ordering, stream_ordering, event_id FROM events"
                " WHERE room_id = ? AND topological_ordering > ?"
                " UNION ALL"
                " SELECT topological_ordering, stream_ordering, event_id FROM events"
                " WHERE room_id = ? AND topological_ordering = ? AND stream_ordering > ?"
                " ORDER BY topological_ordering ASC, stream_ordering ASC LIMIT ?"
            )
            after_args = (
                room_id, token.topological,
                room_id, token.topological, token.stream,
                after_limit,
            )
        else:
            query_before = (
                "SELECT topological_ordering, stream_ordering, event_id FROM events"
                " WHERE room_id = ? AND %s"
                " ORDER BY topological_ordering DESC, stream_ordering DESC LIMIT ?"
            ) % (upper_bound(token, self.database_engine, inclusive=False),)

            before_args = (room_id, before_limit)

            query_after = (
                "SELECT topological_ordering, stream_ordering, event_id FROM events"
                " WHERE room_id = ? AND %s"
                " ORDER BY topological_ordering ASC, stream_ordering ASC LIMIT ?"
            ) % (lower_bound(token, self.database_engine, inclusive=False),)

            after_args = (room_id, after_limit)

        txn.execute(query_before, before_args)

        rows = self.cursor_to_dict(txn)
        events_before = [r["event_id"] for r in rows]

        if rows:
            start_token = str(RoomStreamToken(
                rows[0]["topological_ordering"],
                rows[0]["stream_ordering"] - 1,
            ))
        else:
            start_token = str(RoomStreamToken(
                token.topological,
                token.stream - 1,
            ))

        txn.execute(query_after, after_args)

        rows = self.cursor_to_dict(txn)
        events_after = [r["event_id"] for r in rows]

        if rows:
            end_token = str(RoomStreamToken(
                rows[-1]["topological_ordering"],
                rows[-1]["stream_ordering"],
            ))
        else:
            end_token = str(token)

        return {
            "before": {
                "event_ids": events_before,
                "token": start_token,
            },
            "after": {
                "event_ids": events_after,
                "token": end_token,
            },
        }

    @defer.inlineCallbacks
    def get_all_new_events_stream(self, from_id, current_id, limit):
        """Get all new events"""

        def get_all_new_events_stream_txn(txn):
            sql = (
                "SELECT e.stream_ordering, e.event_id"
                " FROM events AS e"
                " WHERE"
                " ? < e.stream_ordering AND e.stream_ordering <= ?"
                " ORDER BY e.stream_ordering ASC"
                " LIMIT ?"
            )

            txn.execute(sql, (from_id, current_id, limit))
            rows = txn.fetchall()

            upper_bound = current_id
            if len(rows) == limit:
                upper_bound = rows[-1][0]

            return upper_bound, [row[1] for row in rows]

        upper_bound, event_ids = yield self.runInteraction(
            "get_all_new_events_stream", get_all_new_events_stream_txn,
        )

        events = yield self._get_events(event_ids)

        defer.returnValue((upper_bound, events))

    def get_federation_out_pos(self, typ):
        return self._simple_select_one_onecol(
            table="federation_stream_position",
            retcol="stream_id",
            keyvalues={"type": typ},
            desc="get_federation_out_pos"
        )

    def update_federation_out_pos(self, typ, stream_id):
        return self._simple_update_one(
            table="federation_stream_position",
            keyvalues={"type": typ},
            updatevalues={"stream_id": stream_id},
            desc="update_federation_out_pos",
        )
