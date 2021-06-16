# Copyright 2014-2016 OpenMarket Ltd
# Copyright 2017 Vector Creations Ltd
# Copyright 2018-2019 New Vector Ltd
# Copyright 2019 The Matrix.org Foundation C.I.C.
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
import abc
import logging
from collections import namedtuple
from typing import TYPE_CHECKING, Collection, Dict, List, Optional, Set, Tuple

from twisted.internet import defer

from synapse.api.filtering import Filter
from synapse.events import EventBase
from synapse.logging.context import make_deferred_yieldable, run_in_background
from synapse.storage._base import SQLBaseStore
from synapse.storage.database import (
    DatabasePool,
    LoggingTransaction,
    make_in_list_sql_clause,
)
from synapse.storage.databases.main.events_worker import EventsWorkerStore
from synapse.storage.engines import BaseDatabaseEngine, PostgresEngine
from synapse.storage.util.id_generators import MultiWriterIdGenerator
from synapse.types import PersistedEventPosition, RoomStreamToken
from synapse.util.caches.descriptors import cached
from synapse.util.caches.stream_change_cache import StreamChangeCache

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


MAX_STREAM_SIZE = 1000


_STREAM_TOKEN = "stream"
_TOPOLOGICAL_TOKEN = "topological"


# Used as return values for pagination APIs
_EventDictReturn = namedtuple(
    "_EventDictReturn", ("event_id", "topological_ordering", "stream_ordering")
)


def generate_pagination_where_clause(
    direction: str,
    column_names: Tuple[str, str],
    from_token: Optional[Tuple[Optional[int], int]],
    to_token: Optional[Tuple[Optional[int], int]],
    engine: BaseDatabaseEngine,
) -> str:
    """Creates an SQL expression to bound the columns by the pagination
    tokens.

    For example creates an SQL expression like:

        (6, 7) >= (topological_ordering, stream_ordering)
        AND (5, 3) < (topological_ordering, stream_ordering)

    would be generated for dir=b, from_token=(6, 7) and to_token=(5, 3).

    Note that tokens are considered to be after the row they are in, e.g. if
    a row A has a token T, then we consider A to be before T. This convention
    is important when figuring out inequalities for the generated SQL, and
    produces the following result:
        - If paginating forwards then we exclude any rows matching the from
          token, but include those that match the to token.
        - If paginating backwards then we include any rows matching the from
          token, but include those that match the to token.

    Args:
        direction: Whether we're paginating backwards("b") or forwards ("f").
        column_names: The column names to bound. Must *not* be user defined as
            these get inserted directly into the SQL statement without escapes.
        from_token: The start point for the pagination. This is an exclusive
            minimum bound if direction is "f", and an inclusive maximum bound if
            direction is "b".
        to_token: The endpoint point for the pagination. This is an inclusive
            maximum bound if direction is "f", and an exclusive minimum bound if
            direction is "b".
        engine: The database engine to generate the clauses for

    Returns:
        The sql expression
    """
    assert direction in ("b", "f")

    where_clause = []
    if from_token:
        where_clause.append(
            _make_generic_sql_bound(
                bound=">=" if direction == "b" else "<",
                column_names=column_names,
                values=from_token,
                engine=engine,
            )
        )

    if to_token:
        where_clause.append(
            _make_generic_sql_bound(
                bound="<" if direction == "b" else ">=",
                column_names=column_names,
                values=to_token,
                engine=engine,
            )
        )

    return " AND ".join(where_clause)


def _make_generic_sql_bound(
    bound: str,
    column_names: Tuple[str, str],
    values: Tuple[Optional[int], int],
    engine: BaseDatabaseEngine,
) -> str:
    """Create an SQL expression that bounds the given column names by the
    values, e.g. create the equivalent of `(1, 2) < (col1, col2)`.

    Only works with two columns.

    Older versions of SQLite don't support that syntax so we have to expand it
    out manually.

    Args:
        bound: The comparison operator to use. One of ">", "<", ">=",
            "<=", where the values are on the left and columns on the right.
        names: The column names. Must *not* be user defined
            as these get inserted directly into the SQL statement without
            escapes.
        values: The values to bound the columns by. If
            the first value is None then only creates a bound on the second
            column.
        engine: The database engine to generate the SQL for

    Returns:
        The SQL statement
    """

    assert bound in (">", "<", ">=", "<=")

    name1, name2 = column_names
    val1, val2 = values

    if val1 is None:
        val2 = int(val2)
        return "(%d %s %s)" % (val2, bound, name2)

    val1 = int(val1)
    val2 = int(val2)

    if isinstance(engine, PostgresEngine):
        # Postgres doesn't optimise ``(x < a) OR (x=a AND y<b)`` as well
        # as it optimises ``(x,y) < (a,b)`` on multicolumn indexes. So we
        # use the later form when running against postgres.
        return "((%d,%d) %s (%s,%s))" % (val1, val2, bound, name1, name2)

    # We want to generate queries of e.g. the form:
    #
    #   (val1 < name1 OR (val1 = name1 AND val2 <= name2))
    #
    # which is equivalent to (val1, val2) < (name1, name2)

    return """(
        {val1:d} {strict_bound} {name1}
        OR ({val1:d} = {name1} AND {val2:d} {bound} {name2})
    )""".format(
        name1=name1,
        val1=val1,
        name2=name2,
        val2=val2,
        strict_bound=bound[0],  # The first bound must always be strict equality here
        bound=bound,
    )


def _filter_results(
    lower_token: Optional[RoomStreamToken],
    upper_token: Optional[RoomStreamToken],
    instance_name: str,
    topological_ordering: int,
    stream_ordering: int,
) -> bool:
    """Returns True if the event persisted by the given instance at the given
    topological/stream_ordering falls between the two tokens (taking a None
    token to mean unbounded).

    Used to filter results from fetching events in the DB against the given
    tokens. This is necessary to handle the case where the tokens include
    position maps, which we handle by fetching more than necessary from the DB
    and then filtering (rather than attempting to construct a complicated SQL
    query).
    """

    event_historical_tuple = (
        topological_ordering,
        stream_ordering,
    )

    if lower_token:
        if lower_token.topological is not None:
            # If these are historical tokens we compare the `(topological, stream)`
            # tuples.
            if event_historical_tuple <= lower_token.as_historical_tuple():
                return False

        else:
            # If these are live tokens we compare the stream ordering against the
            # writers stream position.
            if stream_ordering <= lower_token.get_stream_pos_for_instance(
                instance_name
            ):
                return False

    if upper_token:
        if upper_token.topological is not None:
            if upper_token.as_historical_tuple() < event_historical_tuple:
                return False
        else:
            if upper_token.get_stream_pos_for_instance(instance_name) < stream_ordering:
                return False

    return True


def filter_to_clause(event_filter: Optional[Filter]) -> Tuple[str, List[str]]:
    # NB: This may create SQL clauses that don't optimise well (and we don't
    # have indices on all possible clauses). E.g. it may create
    # "room_id == X AND room_id != X", which postgres doesn't optimise.

    if not event_filter:
        return "", []

    clauses = []
    args = []

    if event_filter.types:
        clauses.append("(%s)" % " OR ".join("type = ?" for _ in event_filter.types))
        args.extend(event_filter.types)

    for typ in event_filter.not_types:
        clauses.append("type != ?")
        args.append(typ)

    if event_filter.senders:
        clauses.append("(%s)" % " OR ".join("sender = ?" for _ in event_filter.senders))
        args.extend(event_filter.senders)

    for sender in event_filter.not_senders:
        clauses.append("sender != ?")
        args.append(sender)

    if event_filter.rooms:
        clauses.append("(%s)" % " OR ".join("room_id = ?" for _ in event_filter.rooms))
        args.extend(event_filter.rooms)

    for room_id in event_filter.not_rooms:
        clauses.append("room_id != ?")
        args.append(room_id)

    if event_filter.contains_url:
        clauses.append("contains_url = ?")
        args.append(event_filter.contains_url)

    # We're only applying the "labels" filter on the database query, because applying the
    # "not_labels" filter via a SQL query is non-trivial. Instead, we let
    # event_filter.check_fields apply it, which is not as efficient but makes the
    # implementation simpler.
    if event_filter.labels:
        clauses.append("(%s)" % " OR ".join("label = ?" for _ in event_filter.labels))
        args.extend(event_filter.labels)

    return " AND ".join(clauses), args


class StreamWorkerStore(EventsWorkerStore, SQLBaseStore, metaclass=abc.ABCMeta):
    """This is an abstract base class where subclasses must implement
    `get_room_max_stream_ordering` and `get_room_min_stream_ordering`
    which can be called in the initializer.
    """

    def __init__(self, database: DatabasePool, db_conn, hs: "HomeServer"):
        super().__init__(database, db_conn, hs)

        self._instance_name = hs.get_instance_name()
        self._send_federation = hs.should_send_federation()
        self._federation_shard_config = hs.config.worker.federation_shard_config

        # If we're a process that sends federation we may need to reset the
        # `federation_stream_position` table to match the current sharding
        # config. We don't do this now as otherwise two processes could conflict
        # during startup which would cause one to die.
        self._need_to_reset_federation_stream_positions = self._send_federation

        events_max = self.get_room_max_stream_ordering()
        event_cache_prefill, min_event_val = self.db_pool.get_cache_dict(
            db_conn,
            "events",
            entity_column="room_id",
            stream_column="stream_ordering",
            max_value=events_max,
        )
        self._events_stream_cache = StreamChangeCache(
            "EventsRoomStreamChangeCache",
            min_event_val,
            prefilled_cache=event_cache_prefill,
        )
        self._membership_stream_cache = StreamChangeCache(
            "MembershipStreamChangeCache", events_max
        )

        self._stream_order_on_start = self.get_room_max_stream_ordering()

    @abc.abstractmethod
    def get_room_max_stream_ordering(self) -> int:
        raise NotImplementedError()

    @abc.abstractmethod
    def get_room_min_stream_ordering(self) -> int:
        raise NotImplementedError()

    def get_room_max_token(self) -> RoomStreamToken:
        """Get a `RoomStreamToken` that marks the current maximum persisted
        position of the events stream. Useful to get a token that represents
        "now".

        The token returned is a "live" token that may have an instance_map
        component.
        """

        min_pos = self._stream_id_gen.get_current_token()

        positions = {}
        if isinstance(self._stream_id_gen, MultiWriterIdGenerator):
            # The `min_pos` is the minimum position that we know all instances
            # have finished persisting to, so we only care about instances whose
            # positions are ahead of that. (Instance positions can be behind the
            # min position as there are times we can work out that the minimum
            # position is ahead of the naive minimum across all current
            # positions. See MultiWriterIdGenerator for details)
            positions = {
                i: p
                for i, p in self._stream_id_gen.get_positions().items()
                if p > min_pos
            }

        return RoomStreamToken(None, min_pos, positions)

    async def get_room_events_stream_for_rooms(
        self,
        room_ids: Collection[str],
        from_key: RoomStreamToken,
        to_key: RoomStreamToken,
        limit: int = 0,
        order: str = "DESC",
    ) -> Dict[str, Tuple[List[EventBase], RoomStreamToken]]:
        """Get new room events in stream ordering since `from_key`.

        Args:
            room_ids
            from_key: Token from which no events are returned before
            to_key: Token from which no events are returned after. (This
                is typically the current stream token)
            limit: Maximum number of events to return
            order: Either "DESC" or "ASC". Determines which events are
                returned when the result is limited. If "DESC" then the most
                recent `limit` events are returned, otherwise returns the
                oldest `limit` events.

        Returns:
            A map from room id to a tuple containing:
                - list of recent events in the room
                - stream ordering key for the start of the chunk of events returned.
        """
        room_ids = self._events_stream_cache.get_entities_changed(
            room_ids, from_key.stream
        )

        if not room_ids:
            return {}

        results = {}
        room_ids = list(room_ids)
        for rm_ids in (room_ids[i : i + 20] for i in range(0, len(room_ids), 20)):
            res = await make_deferred_yieldable(
                defer.gatherResults(
                    [
                        run_in_background(
                            self.get_room_events_stream_for_room,
                            room_id,
                            from_key,
                            to_key,
                            limit,
                            order=order,
                        )
                        for room_id in rm_ids
                    ],
                    consumeErrors=True,
                )
            )
            results.update(dict(zip(rm_ids, res)))

        return results

    def get_rooms_that_changed(
        self, room_ids: Collection[str], from_key: RoomStreamToken
    ) -> Set[str]:
        """Given a list of rooms and a token, return rooms where there may have
        been changes.
        """
        from_id = from_key.stream
        return {
            room_id
            for room_id in room_ids
            if self._events_stream_cache.has_entity_changed(room_id, from_id)
        }

    async def get_room_events_stream_for_room(
        self,
        room_id: str,
        from_key: RoomStreamToken,
        to_key: RoomStreamToken,
        limit: int = 0,
        order: str = "DESC",
    ) -> Tuple[List[EventBase], RoomStreamToken]:
        """Get new room events in stream ordering since `from_key`.

        Args:
            room_id
            from_key: Token from which no events are returned before
            to_key: Token from which no events are returned after. (This
                is typically the current stream token)
            limit: Maximum number of events to return
            order: Either "DESC" or "ASC". Determines which events are
                returned when the result is limited. If "DESC" then the most
                recent `limit` events are returned, otherwise returns the
                oldest `limit` events.

        Returns:
            The list of events (in ascending order) and the token from the start
            of the chunk of events returned.
        """
        if from_key == to_key:
            return [], from_key

        has_changed = self._events_stream_cache.has_entity_changed(
            room_id, from_key.stream
        )

        if not has_changed:
            return [], from_key

        def f(txn):
            # To handle tokens with a non-empty instance_map we fetch more
            # results than necessary and then filter down
            min_from_id = from_key.stream
            max_to_id = to_key.get_max_stream_pos()

            sql = """
                SELECT event_id, instance_name, topological_ordering, stream_ordering
                FROM events
                WHERE
                    room_id = ?
                    AND not outlier
                    AND stream_ordering > ? AND stream_ordering <= ?
                ORDER BY stream_ordering %s LIMIT ?
            """ % (
                order,
            )
            txn.execute(sql, (room_id, min_from_id, max_to_id, 2 * limit))

            rows = [
                _EventDictReturn(event_id, None, stream_ordering)
                for event_id, instance_name, topological_ordering, stream_ordering in txn
                if _filter_results(
                    from_key,
                    to_key,
                    instance_name,
                    topological_ordering,
                    stream_ordering,
                )
            ][:limit]
            return rows

        rows = await self.db_pool.runInteraction("get_room_events_stream_for_room", f)

        ret = await self.get_events_as_list(
            [r.event_id for r in rows], get_prev_content=True
        )

        self._set_before_and_after(ret, rows, topo_order=False)

        if order.lower() == "desc":
            ret.reverse()

        if rows:
            key = RoomStreamToken(None, min(r.stream_ordering for r in rows))
        else:
            # Assume we didn't get anything because there was nothing to
            # get.
            key = from_key

        return ret, key

    async def get_membership_changes_for_user(
        self, user_id: str, from_key: RoomStreamToken, to_key: RoomStreamToken
    ) -> List[EventBase]:
        if from_key == to_key:
            return []

        if from_key:
            has_changed = self._membership_stream_cache.has_entity_changed(
                user_id, int(from_key.stream)
            )
            if not has_changed:
                return []

        def f(txn):
            # To handle tokens with a non-empty instance_map we fetch more
            # results than necessary and then filter down
            min_from_id = from_key.stream
            max_to_id = to_key.get_max_stream_pos()

            sql = """
                SELECT m.event_id, instance_name, topological_ordering, stream_ordering
                FROM events AS e, room_memberships AS m
                WHERE e.event_id = m.event_id
                    AND m.user_id = ?
                    AND e.stream_ordering > ? AND e.stream_ordering <= ?
                ORDER BY e.stream_ordering ASC
            """
            txn.execute(
                sql,
                (
                    user_id,
                    min_from_id,
                    max_to_id,
                ),
            )

            rows = [
                _EventDictReturn(event_id, None, stream_ordering)
                for event_id, instance_name, topological_ordering, stream_ordering in txn
                if _filter_results(
                    from_key,
                    to_key,
                    instance_name,
                    topological_ordering,
                    stream_ordering,
                )
            ]

            return rows

        rows = await self.db_pool.runInteraction("get_membership_changes_for_user", f)

        ret = await self.get_events_as_list(
            [r.event_id for r in rows], get_prev_content=True
        )

        self._set_before_and_after(ret, rows, topo_order=False)

        return ret

    async def get_recent_events_for_room(
        self, room_id: str, limit: int, end_token: RoomStreamToken
    ) -> Tuple[List[EventBase], RoomStreamToken]:
        """Get the most recent events in the room in topological ordering.

        Args:
            room_id
            limit
            end_token: The stream token representing now.

        Returns:
            A list of events and a token pointing to the start of the returned
            events. The events returned are in ascending order.
        """

        rows, token = await self.get_recent_event_ids_for_room(
            room_id, limit, end_token
        )

        events = await self.get_events_as_list(
            [r.event_id for r in rows], get_prev_content=True
        )

        self._set_before_and_after(events, rows)

        return (events, token)

    async def get_recent_event_ids_for_room(
        self, room_id: str, limit: int, end_token: RoomStreamToken
    ) -> Tuple[List[_EventDictReturn], RoomStreamToken]:
        """Get the most recent events in the room in topological ordering.

        Args:
            room_id
            limit
            end_token: The stream token representing now.

        Returns:
            A list of _EventDictReturn and a token pointing to the start of the
            returned events. The events returned are in ascending order.
        """
        # Allow a zero limit here, and no-op.
        if limit == 0:
            return [], end_token

        rows, token = await self.db_pool.runInteraction(
            "get_recent_event_ids_for_room",
            self._paginate_room_events_txn,
            room_id,
            from_token=end_token,
            limit=limit,
        )

        # We want to return the results in ascending order.
        rows.reverse()

        return rows, token

    async def get_room_event_before_stream_ordering(
        self, room_id: str, stream_ordering: int
    ) -> Optional[Tuple[int, int, str]]:
        """Gets details of the first event in a room at or before a stream ordering

        Args:
            room_id:
            stream_ordering:

        Returns:
            A tuple of (stream ordering, topological ordering, event_id)
        """

        def _f(txn):
            sql = (
                "SELECT stream_ordering, topological_ordering, event_id"
                " FROM events"
                " WHERE room_id = ? AND stream_ordering <= ?"
                " AND NOT outlier"
                " ORDER BY stream_ordering DESC"
                " LIMIT 1"
            )
            txn.execute(sql, (room_id, stream_ordering))
            return txn.fetchone()

        return await self.db_pool.runInteraction(
            "get_room_event_before_stream_ordering", _f
        )

    async def get_room_events_max_id(self, room_id: Optional[str] = None) -> str:
        """Returns the current token for rooms stream.

        By default, it returns the current global stream token. Specifying a
        `room_id` causes it to return the current room specific topological
        token.
        """
        token = self.get_room_max_stream_ordering()
        if room_id is None:
            return "s%d" % (token,)
        else:
            topo = await self.db_pool.runInteraction(
                "_get_max_topological_txn", self._get_max_topological_txn, room_id
            )
            return "t%d-%d" % (topo, token)

    def get_stream_id_for_event_txn(
        self,
        txn: LoggingTransaction,
        event_id: str,
        allow_none=False,
    ) -> int:
        return self.db_pool.simple_select_one_onecol_txn(
            txn=txn,
            table="events",
            keyvalues={"event_id": event_id},
            retcol="stream_ordering",
            allow_none=allow_none,
        )

    async def get_position_for_event(self, event_id: str) -> PersistedEventPosition:
        """Get the persisted position for an event"""
        row = await self.db_pool.simple_select_one(
            table="events",
            keyvalues={"event_id": event_id},
            retcols=("stream_ordering", "instance_name"),
            desc="get_position_for_event",
        )

        return PersistedEventPosition(
            row["instance_name"] or "master", row["stream_ordering"]
        )

    async def get_topological_token_for_event(self, event_id: str) -> RoomStreamToken:
        """The stream token for an event
        Args:
            event_id: The id of the event to look up a stream token for.
        Raises:
            StoreError if the event wasn't in the database.
        Returns:
            A `RoomStreamToken` topological token.
        """
        row = await self.db_pool.simple_select_one(
            table="events",
            keyvalues={"event_id": event_id},
            retcols=("stream_ordering", "topological_ordering"),
            desc="get_topological_token_for_event",
        )
        return RoomStreamToken(row["topological_ordering"], row["stream_ordering"])

    async def get_current_topological_token(self, room_id: str, stream_key: int) -> int:
        """Gets the topological token in a room after or at the given stream
        ordering.

        Args:
            room_id
            stream_key
        """
        sql = (
            "SELECT coalesce(MIN(topological_ordering), 0) FROM events"
            " WHERE room_id = ? AND stream_ordering >= ?"
        )
        row = await self.db_pool.execute(
            "get_current_topological_token", None, sql, room_id, stream_key
        )
        return row[0][0] if row else 0

    def _get_max_topological_txn(self, txn: LoggingTransaction, room_id: str) -> int:
        txn.execute(
            "SELECT MAX(topological_ordering) FROM events WHERE room_id = ?",
            (room_id,),
        )

        rows = txn.fetchall()
        return rows[0][0] if rows else 0

    @staticmethod
    def _set_before_and_after(
        events: List[EventBase], rows: List[_EventDictReturn], topo_order: bool = True
    ):
        """Inserts ordering information to events' internal metadata from
        the DB rows.

        Args:
            events
            rows
            topo_order: Whether the events were ordered topologically or by stream
                ordering. If true then all rows should have a non null
                topological_ordering.
        """
        for event, row in zip(events, rows):
            stream = row.stream_ordering
            if topo_order and row.topological_ordering:
                topo = row.topological_ordering
            else:
                topo = None
            internal = event.internal_metadata
            internal.before = RoomStreamToken(topo, stream - 1)
            internal.after = RoomStreamToken(topo, stream)
            internal.order = (int(topo) if topo else 0, int(stream))

    async def get_events_around(
        self,
        room_id: str,
        event_id: str,
        before_limit: int,
        after_limit: int,
        event_filter: Optional[Filter] = None,
    ) -> dict:
        """Retrieve events and pagination tokens around a given event in a
        room.
        """

        results = await self.db_pool.runInteraction(
            "get_events_around",
            self._get_events_around_txn,
            room_id,
            event_id,
            before_limit,
            after_limit,
            event_filter,
        )

        events_before = await self.get_events_as_list(
            list(results["before"]["event_ids"]), get_prev_content=True
        )

        events_after = await self.get_events_as_list(
            list(results["after"]["event_ids"]), get_prev_content=True
        )

        return {
            "events_before": events_before,
            "events_after": events_after,
            "start": results["before"]["token"],
            "end": results["after"]["token"],
        }

    def _get_events_around_txn(
        self,
        txn: LoggingTransaction,
        room_id: str,
        event_id: str,
        before_limit: int,
        after_limit: int,
        event_filter: Optional[Filter],
    ) -> dict:
        """Retrieves event_ids and pagination tokens around a given event in a
        room.

        Args:
            room_id
            event_id
            before_limit
            after_limit
            event_filter

        Returns:
            dict
        """

        results = self.db_pool.simple_select_one_txn(
            txn,
            "events",
            keyvalues={"event_id": event_id, "room_id": room_id},
            retcols=["stream_ordering", "topological_ordering"],
        )

        # This cannot happen as `allow_none=False`.
        assert results is not None

        # Paginating backwards includes the event at the token, but paginating
        # forward doesn't.
        before_token = RoomStreamToken(
            results["topological_ordering"] - 1, results["stream_ordering"]
        )

        after_token = RoomStreamToken(
            results["topological_ordering"], results["stream_ordering"]
        )

        rows, start_token = self._paginate_room_events_txn(
            txn,
            room_id,
            before_token,
            direction="b",
            limit=before_limit,
            event_filter=event_filter,
        )
        events_before = [r.event_id for r in rows]

        rows, end_token = self._paginate_room_events_txn(
            txn,
            room_id,
            after_token,
            direction="f",
            limit=after_limit,
            event_filter=event_filter,
        )
        events_after = [r.event_id for r in rows]

        return {
            "before": {"event_ids": events_before, "token": start_token},
            "after": {"event_ids": events_after, "token": end_token},
        }

    async def get_all_new_events_stream(
        self, from_id: int, current_id: int, limit: int
    ) -> Tuple[int, List[EventBase]]:
        """Get all new events

        Returns all events with from_id < stream_ordering <= current_id.

        Args:
            from_id:  the stream_ordering of the last event we processed
            current_id:  the stream_ordering of the most recently processed event
            limit: the maximum number of events to return

        Returns:
            A tuple of (next_id, events), where `next_id` is the next value to
            pass as `from_id` (it will either be the stream_ordering of the
            last returned event, or, if fewer than `limit` events were found,
            the `current_id`).
        """

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

        upper_bound, event_ids = await self.db_pool.runInteraction(
            "get_all_new_events_stream", get_all_new_events_stream_txn
        )

        events = await self.get_events_as_list(event_ids)

        return upper_bound, events

    async def get_federation_out_pos(self, typ: str) -> int:
        if self._need_to_reset_federation_stream_positions:
            await self.db_pool.runInteraction(
                "_reset_federation_positions_txn", self._reset_federation_positions_txn
            )
            self._need_to_reset_federation_stream_positions = False

        return await self.db_pool.simple_select_one_onecol(
            table="federation_stream_position",
            retcol="stream_id",
            keyvalues={"type": typ, "instance_name": self._instance_name},
            desc="get_federation_out_pos",
        )

    async def update_federation_out_pos(self, typ: str, stream_id: int) -> None:
        if self._need_to_reset_federation_stream_positions:
            await self.db_pool.runInteraction(
                "_reset_federation_positions_txn", self._reset_federation_positions_txn
            )
            self._need_to_reset_federation_stream_positions = False

        await self.db_pool.simple_update_one(
            table="federation_stream_position",
            keyvalues={"type": typ, "instance_name": self._instance_name},
            updatevalues={"stream_id": stream_id},
            desc="update_federation_out_pos",
        )

    def _reset_federation_positions_txn(self, txn: LoggingTransaction) -> None:
        """Fiddles with the `federation_stream_position` table to make it match
        the configured federation sender instances during start up.
        """

        # The federation sender instances may have changed, so we need to
        # massage the `federation_stream_position` table to have a row per type
        # per instance sending federation. If there is a mismatch we update the
        # table with the correct rows using the *minimum* stream ID seen. This
        # may result in resending of events/EDUs to remote servers, but that is
        # preferable to dropping them.

        if not self._send_federation:
            return

        # Pull out the configured instances. If we don't have a shard config then
        # we assume that we're the only instance sending.
        configured_instances = self._federation_shard_config.instances
        if not configured_instances:
            configured_instances = [self._instance_name]
        elif self._instance_name not in configured_instances:
            return

        instances_in_table = self.db_pool.simple_select_onecol_txn(
            txn,
            table="federation_stream_position",
            keyvalues={},
            retcol="instance_name",
        )

        if set(instances_in_table) == set(configured_instances):
            # Nothing to do
            return

        sql = """
            SELECT type, MIN(stream_id) FROM federation_stream_position
            GROUP BY type
        """
        txn.execute(sql)
        min_positions = {typ: pos for typ, pos in txn}  # Map from type -> min position

        # Ensure we do actually have some values here
        assert set(min_positions) == {"federation", "events"}

        sql = """
            DELETE FROM federation_stream_position
            WHERE NOT (%s)
        """
        clause, args = make_in_list_sql_clause(
            txn.database_engine, "instance_name", configured_instances
        )
        txn.execute(sql % (clause,), args)

        for typ, stream_id in min_positions.items():
            self.db_pool.simple_upsert_txn(
                txn,
                table="federation_stream_position",
                keyvalues={"type": typ, "instance_name": self._instance_name},
                values={"stream_id": stream_id},
            )

    def has_room_changed_since(self, room_id: str, stream_id: int) -> bool:
        return self._events_stream_cache.has_entity_changed(room_id, stream_id)

    def _paginate_room_events_txn(
        self,
        txn: LoggingTransaction,
        room_id: str,
        from_token: RoomStreamToken,
        to_token: Optional[RoomStreamToken] = None,
        direction: str = "b",
        limit: int = -1,
        event_filter: Optional[Filter] = None,
    ) -> Tuple[List[_EventDictReturn], RoomStreamToken]:
        """Returns list of events before or after a given token.

        Args:
            txn
            room_id
            from_token: The token used to stream from
            to_token: A token which if given limits the results to only those before
            direction: Either 'b' or 'f' to indicate whether we are paginating
                forwards or backwards from `from_key`.
            limit: The maximum number of events to return.
            event_filter: If provided filters the events to
                those that match the filter.

        Returns:
            A list of _EventDictReturn and a token that points to the end of the
            result set. If no events are returned then the end of the stream has
            been reached (i.e. there are no events between `from_token` and
            `to_token`), or `limit` is zero.
        """

        assert int(limit) >= 0

        # Tokens really represent positions between elements, but we use
        # the convention of pointing to the event before the gap. Hence
        # we have a bit of asymmetry when it comes to equalities.
        args = [False, room_id]
        if direction == "b":
            order = "DESC"
        else:
            order = "ASC"

        # The bounds for the stream tokens are complicated by the fact
        # that we need to handle the instance_map part of the tokens. We do this
        # by fetching all events between the min stream token and the maximum
        # stream token (as returned by `RoomStreamToken.get_max_stream_pos`) and
        # then filtering the results.
        if from_token.topological is not None:
            from_bound = (
                from_token.as_historical_tuple()
            )  # type: Tuple[Optional[int], int]
        elif direction == "b":
            from_bound = (
                None,
                from_token.get_max_stream_pos(),
            )
        else:
            from_bound = (
                None,
                from_token.stream,
            )

        to_bound = None  # type: Optional[Tuple[Optional[int], int]]
        if to_token:
            if to_token.topological is not None:
                to_bound = to_token.as_historical_tuple()
            elif direction == "b":
                to_bound = (
                    None,
                    to_token.stream,
                )
            else:
                to_bound = (
                    None,
                    to_token.get_max_stream_pos(),
                )

        bounds = generate_pagination_where_clause(
            direction=direction,
            column_names=("topological_ordering", "stream_ordering"),
            from_token=from_bound,
            to_token=to_bound,
            engine=self.database_engine,
        )

        filter_clause, filter_args = filter_to_clause(event_filter)

        if filter_clause:
            bounds += " AND " + filter_clause
            args.extend(filter_args)

        # We fetch more events as we'll filter the result set
        args.append(int(limit) * 2)

        select_keywords = "SELECT"
        join_clause = ""
        if event_filter and event_filter.labels:
            # If we're not filtering on a label, then joining on event_labels will
            # return as many row for a single event as the number of labels it has. To
            # avoid this, only join if we're filtering on at least one label.
            join_clause = """
                LEFT JOIN event_labels
                USING (event_id, room_id, topological_ordering)
            """
            if len(event_filter.labels) > 1:
                # Using DISTINCT in this SELECT query is quite expensive, because it
                # requires the engine to sort on the entire (not limited) result set,
                # i.e. the entire events table. We only need to use it when we're
                # filtering on more than two labels, because that's the only scenario
                # in which we can possibly to get multiple times the same event ID in
                # the results.
                select_keywords += "DISTINCT"

        sql = """
            %(select_keywords)s
                event_id, instance_name,
                topological_ordering, stream_ordering
            FROM events
            %(join_clause)s
            WHERE outlier = ? AND room_id = ? AND %(bounds)s
            ORDER BY topological_ordering %(order)s,
            stream_ordering %(order)s LIMIT ?
        """ % {
            "select_keywords": select_keywords,
            "join_clause": join_clause,
            "bounds": bounds,
            "order": order,
        }

        txn.execute(sql, args)

        # Filter the result set.
        rows = [
            _EventDictReturn(event_id, topological_ordering, stream_ordering)
            for event_id, instance_name, topological_ordering, stream_ordering in txn
            if _filter_results(
                lower_token=to_token if direction == "b" else from_token,
                upper_token=from_token if direction == "b" else to_token,
                instance_name=instance_name,
                topological_ordering=topological_ordering,
                stream_ordering=stream_ordering,
            )
        ][:limit]

        if rows:
            topo = rows[-1].topological_ordering
            toke = rows[-1].stream_ordering
            if direction == "b":
                # Tokens are positions between events.
                # This token points *after* the last event in the chunk.
                # We need it to point to the event before it in the chunk
                # when we are going backwards so we subtract one from the
                # stream part.
                toke -= 1
            next_token = RoomStreamToken(topo, toke)
        else:
            # TODO (erikj): We should work out what to do here instead.
            next_token = to_token if to_token else from_token

        return rows, next_token

    async def paginate_room_events(
        self,
        room_id: str,
        from_key: RoomStreamToken,
        to_key: Optional[RoomStreamToken] = None,
        direction: str = "b",
        limit: int = -1,
        event_filter: Optional[Filter] = None,
    ) -> Tuple[List[EventBase], RoomStreamToken]:
        """Returns list of events before or after a given token.

        Args:
            room_id
            from_key: The token used to stream from
            to_key: A token which if given limits the results to only those before
            direction: Either 'b' or 'f' to indicate whether we are paginating
                forwards or backwards from `from_key`.
            limit: The maximum number of events to return.
            event_filter: If provided filters the events to those that match the filter.

        Returns:
            The results as a list of events and a token that points to the end
            of the result set. If no events are returned then the end of the
            stream has been reached (i.e. there are no events between `from_key`
            and `to_key`).
        """

        rows, token = await self.db_pool.runInteraction(
            "paginate_room_events",
            self._paginate_room_events_txn,
            room_id,
            from_key,
            to_key,
            direction,
            limit,
            event_filter,
        )

        events = await self.get_events_as_list(
            [r.event_id for r in rows], get_prev_content=True
        )

        self._set_before_and_after(events, rows)

        return (events, token)

    @cached()
    async def get_id_for_instance(self, instance_name: str) -> int:
        """Get a unique, immutable ID that corresponds to the given Synapse worker instance."""

        def _get_id_for_instance_txn(txn):
            instance_id = self.db_pool.simple_select_one_onecol_txn(
                txn,
                table="instance_map",
                keyvalues={"instance_name": instance_name},
                retcol="instance_id",
                allow_none=True,
            )
            if instance_id is not None:
                return instance_id

            # If we don't have an entry upsert one.
            #
            # We could do this before the first check, and rely on the cache for
            # efficiency, but each UPSERT causes the next ID to increment which
            # can quickly bloat the size of the generated IDs for new instances.
            self.db_pool.simple_upsert_txn(
                txn,
                table="instance_map",
                keyvalues={"instance_name": instance_name},
                values={},
            )

            return self.db_pool.simple_select_one_onecol_txn(
                txn,
                table="instance_map",
                keyvalues={"instance_name": instance_name},
                retcol="instance_id",
            )

        return await self.db_pool.runInteraction(
            "get_id_for_instance", _get_id_for_instance_txn
        )

    @cached()
    async def get_name_from_instance_id(self, instance_id: int) -> str:
        """Get the instance name from an ID previously returned by
        `get_id_for_instance`.
        """

        return await self.db_pool.simple_select_one_onecol(
            table="instance_map",
            keyvalues={"instance_id": instance_id},
            retcol="instance_name",
            desc="get_name_from_instance_id",
        )


class StreamStore(StreamWorkerStore):
    def get_room_max_stream_ordering(self) -> int:
        return self._stream_id_gen.get_current_token()

    def get_room_min_stream_ordering(self) -> int:
        return self._backfill_id_gen.get_current_token()
