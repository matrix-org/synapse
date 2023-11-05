# Copyright 2019 New Vector Ltd
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

import logging
from typing import (
    TYPE_CHECKING,
    Collection,
    Dict,
    FrozenSet,
    Iterable,
    List,
    Mapping,
    Optional,
    Sequence,
    Set,
    Tuple,
    Union,
    cast,
)

import attr

from synapse.api.constants import MAIN_TIMELINE, Direction, RelationTypes
from synapse.api.errors import SynapseError
from synapse.events import EventBase
from synapse.storage._base import SQLBaseStore
from synapse.storage.database import (
    DatabasePool,
    LoggingDatabaseConnection,
    LoggingTransaction,
    make_in_list_sql_clause,
)
from synapse.storage.databases.main.stream import (
    generate_next_token,
    generate_pagination_bounds,
    generate_pagination_where_clause,
)
from synapse.storage.engines import PostgresEngine
from synapse.types import JsonDict, MultiWriterStreamToken, StreamKeyType, StreamToken
from synapse.util.caches.descriptors import cached, cachedList

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


@attr.s(slots=True, frozen=True, auto_attribs=True)
class ThreadsNextBatch:
    topological_ordering: int
    stream_ordering: int

    def __str__(self) -> str:
        return f"{self.topological_ordering}_{self.stream_ordering}"

    @classmethod
    def from_string(cls, string: str) -> "ThreadsNextBatch":
        """
        Creates a ThreadsNextBatch from its textual representation.
        """
        try:
            keys = (int(s) for s in string.split("_"))
            return cls(*keys)
        except Exception:
            raise SynapseError(400, "Invalid threads token")


@attr.s(slots=True, frozen=True, auto_attribs=True)
class _RelatedEvent:
    """
    Contains enough information about a related event in order to properly filter
    events from ignored users.
    """

    # The event ID of the related event.
    event_id: str
    # The sender of the related event.
    sender: str


class RelationsWorkerStore(SQLBaseStore):
    def __init__(
        self,
        database: DatabasePool,
        db_conn: LoggingDatabaseConnection,
        hs: "HomeServer",
    ):
        super().__init__(database, db_conn, hs)

        self.db_pool.updates.register_background_update_handler(
            "threads_backfill", self._backfill_threads
        )

    async def _backfill_threads(self, progress: JsonDict, batch_size: int) -> int:
        """Backfill the threads table."""

        def threads_backfill_txn(txn: LoggingTransaction) -> int:
            last_thread_id = progress.get("last_thread_id", "")

            # Get the latest event in each thread by topo ordering / stream ordering.
            #
            # Note that the MAX(event_id) is needed to abide by the rules of group by,
            # but doesn't actually do anything since there should only be a single event
            # ID per topo/stream ordering pair.
            sql = f"""
            SELECT room_id, relates_to_id, MAX(topological_ordering), MAX(stream_ordering), MAX(event_id)
            FROM event_relations
            INNER JOIN events USING (event_id)
            WHERE
                relates_to_id > ? AND
                relation_type = '{RelationTypes.THREAD}'
            GROUP BY room_id, relates_to_id
            ORDER BY relates_to_id
            LIMIT ?
            """
            txn.execute(sql, (last_thread_id, batch_size))

            # No more rows to process.
            rows = txn.fetchall()
            if not rows:
                return 0

            # Insert the rows into the threads table. If a matching thread already exists,
            # assume it is from a newer event.
            sql = """
            INSERT INTO threads (room_id, thread_id, topological_ordering, stream_ordering, latest_event_id)
            VALUES %s
            ON CONFLICT (room_id, thread_id)
            DO NOTHING
            """
            if isinstance(txn.database_engine, PostgresEngine):
                txn.execute_values(sql % ("?",), rows, fetch=False)
            else:
                txn.execute_batch(sql % ("(?, ?, ?, ?, ?)",), rows)

            # Mark the progress.
            self.db_pool.updates._background_update_progress_txn(
                txn, "threads_backfill", {"last_thread_id": rows[-1][1]}
            )

            return txn.rowcount

        result = await self.db_pool.runInteraction(
            "threads_backfill", threads_backfill_txn
        )

        if not result:
            await self.db_pool.updates._end_background_update("threads_backfill")

        return result

    @cached(uncached_args=("event",), tree=True)
    async def get_relations_for_event(
        self,
        event_id: str,
        event: EventBase,
        room_id: str,
        relation_type: Optional[str] = None,
        event_type: Optional[str] = None,
        limit: int = 5,
        direction: Direction = Direction.BACKWARDS,
        from_token: Optional[StreamToken] = None,
        to_token: Optional[StreamToken] = None,
        recurse: bool = False,
    ) -> Tuple[Sequence[_RelatedEvent], Optional[StreamToken]]:
        """Get a list of relations for an event, ordered by topological ordering.

        Args:
            event_id: Fetch events that relate to this event ID.
            event: The matching EventBase to event_id.
            room_id: The room the event belongs to.
            relation_type: Only fetch events with this relation type, if given.
            event_type: Only fetch events with this event type, if given.
            limit: Only fetch the most recent `limit` events.
            direction: Whether to fetch the most recent first (backwards) or the
                oldest first (forwards).
            from_token: Fetch rows from the given token, or from the start if None.
            to_token: Fetch rows up to the given token, or up to the end if None.
            recurse: Whether to recursively find relations.

        Returns:
            A tuple of:
                A list of related event IDs & their senders.

                The next stream token, if one exists.
        """
        # We don't use `event_id`, it's there so that we can cache based on
        # it. The `event_id` must match the `event.event_id`.
        assert event.event_id == event_id

        # Ensure bad limits aren't being passed in.
        assert limit >= 0

        where_clause = ["room_id = ?"]
        where_args: List[Union[str, int]] = [room_id]
        is_redacted = event.internal_metadata.is_redacted()

        if relation_type is not None:
            where_clause.append("relation_type = ?")
            where_args.append(relation_type)

        if event_type is not None:
            where_clause.append("type = ?")
            where_args.append(event_type)

        order, from_bound, to_bound = generate_pagination_bounds(
            direction,
            from_token.room_key if from_token else None,
            to_token.room_key if to_token else None,
        )

        pagination_clause = generate_pagination_where_clause(
            direction=direction,
            column_names=("topological_ordering", "stream_ordering"),
            from_token=from_bound,
            to_token=to_bound,
            engine=self.database_engine,
        )

        if pagination_clause:
            where_clause.append(pagination_clause)

        # If a recursive query is requested then the filters are applied after
        # recursively following relationships from the requested event to children
        # up to 3-relations deep.
        #
        # If no recursion is needed then the event_relations table is queried
        # for direct children of the requested event.
        if recurse:
            sql = """
                WITH RECURSIVE related_events AS (
                    SELECT event_id, relation_type, relates_to_id, 0 AS depth
                    FROM event_relations
                    WHERE relates_to_id = ?
                    UNION SELECT e.event_id, e.relation_type, e.relates_to_id, depth + 1
                    FROM event_relations e
                    INNER JOIN related_events r ON r.event_id = e.relates_to_id
                    WHERE depth <= 3
                )
                SELECT event_id, relation_type, sender, topological_ordering, stream_ordering
                FROM related_events
                INNER JOIN events USING (event_id)
                WHERE %s
                ORDER BY topological_ordering %s, stream_ordering %s
                LIMIT ?;
            """ % (
                " AND ".join(where_clause),
                order,
                order,
            )
        else:
            sql = """
                SELECT event_id, relation_type, sender, topological_ordering, stream_ordering
                FROM event_relations
                INNER JOIN events USING (event_id)
                WHERE relates_to_id = ? AND %s
                ORDER BY topological_ordering %s, stream_ordering %s
                LIMIT ?
            """ % (
                " AND ".join(where_clause),
                order,
                order,
            )

        def _get_recent_references_for_event_txn(
            txn: LoggingTransaction,
        ) -> Tuple[List[_RelatedEvent], Optional[StreamToken]]:
            txn.execute(sql, [event.event_id] + where_args + [limit + 1])

            events = []
            topo_orderings: List[int] = []
            stream_orderings: List[int] = []
            for event_id, relation_type, sender, topo_ordering, stream_ordering in cast(
                List[Tuple[str, str, str, int, int]], txn
            ):
                # Do not include edits for redacted events as they leak event
                # content.
                if not is_redacted or relation_type != RelationTypes.REPLACE:
                    events.append(_RelatedEvent(event_id, sender))
                    topo_orderings.append(topo_ordering)
                    stream_orderings.append(stream_ordering)

            # If there are more events, generate the next pagination key from the
            # last event returned.
            next_token = None
            if len(events) > limit:
                # Instead of using the last row (which tells us there is more
                # data), use the last row to be returned.
                events = events[:limit]
                topo_orderings = topo_orderings[:limit]
                stream_orderings = stream_orderings[:limit]

                next_key = generate_next_token(
                    direction, topo_orderings[-1], stream_orderings[-1]
                )

                if from_token:
                    next_token = from_token.copy_and_replace(
                        StreamKeyType.ROOM, next_key
                    )
                else:
                    next_token = StreamToken(
                        room_key=next_key,
                        presence_key=0,
                        typing_key=0,
                        receipt_key=MultiWriterStreamToken(stream=0),
                        account_data_key=0,
                        push_rules_key=0,
                        to_device_key=0,
                        device_list_key=0,
                        groups_key=0,
                        un_partial_stated_rooms_key=0,
                    )

            return events[:limit], next_token

        return await self.db_pool.runInteraction(
            "get_recent_references_for_event", _get_recent_references_for_event_txn
        )

    async def get_all_relations_for_event_with_types(
        self,
        event_id: str,
        relation_types: List[str],
    ) -> List[str]:
        """Get the event IDs of all events that have a relation to the given event with
        one of the given relation types.

        Args:
            event_id: The event for which to look for related events.
            relation_types: The types of relations to look for.

        Returns:
            A list of the IDs of the events that relate to the given event with one of
            the given relation types.
        """

        def get_all_relation_ids_for_event_with_types_txn(
            txn: LoggingTransaction,
        ) -> List[str]:
            rows = cast(
                List[Tuple[str]],
                self.db_pool.simple_select_many_txn(
                    txn=txn,
                    table="event_relations",
                    column="relation_type",
                    iterable=relation_types,
                    keyvalues={"relates_to_id": event_id},
                    retcols=["event_id"],
                ),
            )

            return [row[0] for row in rows]

        return await self.db_pool.runInteraction(
            desc="get_all_relation_ids_for_event_with_types",
            func=get_all_relation_ids_for_event_with_types_txn,
        )

    async def get_all_relations_for_event(
        self,
        event_id: str,
    ) -> List[str]:
        """Get the event IDs of all events that have a relation to the given event.

        Args:
            event_id: The event for which to look for related events.

        Returns:
            A list of the IDs of the events that relate to the given event.
        """

        def get_all_relation_ids_for_event_txn(
            txn: LoggingTransaction,
        ) -> List[str]:
            rows = cast(
                List[Tuple[str]],
                self.db_pool.simple_select_list_txn(
                    txn=txn,
                    table="event_relations",
                    keyvalues={"relates_to_id": event_id},
                    retcols=["event_id"],
                ),
            )

            return [row[0] for row in rows]

        return await self.db_pool.runInteraction(
            desc="get_all_relation_ids_for_event",
            func=get_all_relation_ids_for_event_txn,
        )

    async def event_includes_relation(self, event_id: str) -> bool:
        """Check if the given event relates to another event.

        An event has a relation if it has a valid m.relates_to with a rel_type
        and event_id in the content:

        {
            "content": {
                "m.relates_to": {
                    "rel_type": "m.replace",
                    "event_id": "$other_event_id"
                }
            }
        }

        Args:
            event_id: The event to check.

        Returns:
            True if the event includes a valid relation.
        """

        result = await self.db_pool.simple_select_one_onecol(
            table="event_relations",
            keyvalues={"event_id": event_id},
            retcol="event_id",
            allow_none=True,
            desc="event_includes_relation",
        )
        return result is not None

    async def event_is_target_of_relation(self, parent_id: str) -> bool:
        """Check if the given event is the target of another event's relation.

        An event is the target of an event relation if it has a valid
        m.relates_to with a rel_type and event_id pointing to parent_id in the
        content:

        {
            "content": {
                "m.relates_to": {
                    "rel_type": "m.replace",
                    "event_id": "$parent_id"
                }
            }
        }

        Args:
            parent_id: The event to check.

        Returns:
            True if the event is the target of another event's relation.
        """

        result = await self.db_pool.simple_select_one_onecol(
            table="event_relations",
            keyvalues={"relates_to_id": parent_id},
            retcol="event_id",
            allow_none=True,
            desc="event_is_target_of_relation",
        )
        return result is not None

    @cached()  # type: ignore[synapse-@cached-mutable]
    async def get_references_for_event(self, event_id: str) -> List[JsonDict]:
        raise NotImplementedError()

    @cachedList(cached_method_name="get_references_for_event", list_name="event_ids")
    async def get_references_for_events(
        self, event_ids: Collection[str]
    ) -> Mapping[str, Optional[Sequence[_RelatedEvent]]]:
        """Get a list of references to the given events.

        Args:
            event_ids: Fetch events that relate to these event IDs.

        Returns:
            A map of event IDs to a list of related event IDs (and their senders).
        """

        clause, args = make_in_list_sql_clause(
            self.database_engine, "relates_to_id", event_ids
        )
        args.append(RelationTypes.REFERENCE)

        sql = f"""
            SELECT relates_to_id, ref.event_id, ref.sender
            FROM events AS ref
            INNER JOIN event_relations USING (event_id)
            INNER JOIN events AS parent ON
                parent.event_id = relates_to_id
                AND parent.room_id = ref.room_id
            WHERE
                {clause}
                AND relation_type = ?
            ORDER BY ref.topological_ordering, ref.stream_ordering
        """

        def _get_references_for_events_txn(
            txn: LoggingTransaction,
        ) -> Mapping[str, List[_RelatedEvent]]:
            txn.execute(sql, args)

            result: Dict[str, List[_RelatedEvent]] = {}
            for relates_to_id, event_id, sender in cast(
                List[Tuple[str, str, str]], txn
            ):
                result.setdefault(relates_to_id, []).append(
                    _RelatedEvent(event_id, sender)
                )

            return result

        return await self.db_pool.runInteraction(
            "_get_references_for_events_txn", _get_references_for_events_txn
        )

    @cached()  # type: ignore[synapse-@cached-mutable]
    def get_applicable_edit(self, event_id: str) -> Optional[EventBase]:
        raise NotImplementedError()

    # TODO: This returns a mutable object, which is generally bad.
    @cachedList(cached_method_name="get_applicable_edit", list_name="event_ids")  # type: ignore[synapse-@cached-mutable]
    async def get_applicable_edits(
        self, event_ids: Collection[str]
    ) -> Mapping[str, Optional[EventBase]]:
        """Get the most recent edit (if any) that has happened for the given
        events.

        Correctly handles checking whether edits were allowed to happen.

        Args:
            event_ids: The original event IDs

        Returns:
            A map of the most recent edit for each event. If there are no edits,
            the event will map to None.
        """

        # We only allow edits for events that have the same sender and event type.
        # We can't assert these things during regular event auth so we have to do
        # the checks post hoc.

        # Fetches latest edit that has the same type and sender as the original.
        if isinstance(self.database_engine, PostgresEngine):
            # The `DISTINCT ON` clause will pick the *first* row it encounters,
            # so ordering by origin server ts + event ID desc will ensure we get
            # the latest edit.
            sql = """
                SELECT DISTINCT ON (original.event_id) original.event_id, edit.event_id FROM events AS edit
                INNER JOIN event_relations USING (event_id)
                INNER JOIN events AS original ON
                    original.event_id = relates_to_id
                    AND edit.type = original.type
                    AND edit.sender = original.sender
                    AND edit.room_id = original.room_id
                WHERE
                    %s
                    AND relation_type = ?
                ORDER by original.event_id DESC, edit.origin_server_ts DESC, edit.event_id DESC
            """
        else:
            # SQLite uses a simplified query which returns all edits for an
            # original event. The results are then de-duplicated when turned into
            # a dict. Due to the chosen ordering, the latest edit stomps on
            # earlier edits.
            sql = """
                SELECT original.event_id, edit.event_id FROM events AS edit
                INNER JOIN event_relations USING (event_id)
                INNER JOIN events AS original ON
                    original.event_id = relates_to_id
                    AND edit.type = original.type
                    AND edit.sender = original.sender
                    AND edit.room_id = original.room_id
                WHERE
                    %s
                    AND relation_type = ?
                ORDER by edit.origin_server_ts, edit.event_id
            """

        def _get_applicable_edits_txn(txn: LoggingTransaction) -> Dict[str, str]:
            clause, args = make_in_list_sql_clause(
                txn.database_engine, "relates_to_id", event_ids
            )
            args.append(RelationTypes.REPLACE)

            txn.execute(sql % (clause,), args)
            return dict(cast(Iterable[Tuple[str, str]], txn.fetchall()))

        edit_ids = await self.db_pool.runInteraction(
            "get_applicable_edits", _get_applicable_edits_txn
        )

        edits = await self.get_events(edit_ids.values())  # type: ignore[attr-defined]

        # Map to the original event IDs to the edit events.
        #
        # There might not be an edit event due to there being no edits or
        # due to the event not being known, either case is treated the same.
        return {
            original_event_id: edits.get(edit_ids.get(original_event_id))
            for original_event_id in event_ids
        }

    @cached()  # type: ignore[synapse-@cached-mutable]
    def get_thread_summary(self, event_id: str) -> Optional[Tuple[int, EventBase]]:
        raise NotImplementedError()

    # TODO: This returns a mutable object, which is generally bad.
    @cachedList(cached_method_name="get_thread_summary", list_name="event_ids")  # type: ignore[synapse-@cached-mutable]
    async def get_thread_summaries(
        self, event_ids: Collection[str]
    ) -> Mapping[str, Optional[Tuple[int, EventBase]]]:
        """Get the number of threaded replies and the latest reply (if any) for the given events.

        Args:
            event_ids: Summarize the thread related to this event ID.

        Returns:
            A map of the thread summary each event. A missing event implies there
            are no threaded replies.

            Each summary is a tuple of:
                The number of events in the thread.
                The most recent event in the thread.
        """

        def _get_thread_summaries_txn(
            txn: LoggingTransaction,
        ) -> Tuple[Dict[str, int], Dict[str, str]]:
            # Fetch the count of threaded events and the latest event ID.
            # TODO Should this only allow m.room.message events.
            if isinstance(self.database_engine, PostgresEngine):
                # The `DISTINCT ON` clause will pick the *first* row it encounters,
                # so ordering by topological ordering + stream ordering desc will
                # ensure we get the latest event in the thread.
                sql = """
                    SELECT DISTINCT ON (parent.event_id) parent.event_id, child.event_id FROM events AS child
                    INNER JOIN event_relations USING (event_id)
                    INNER JOIN events AS parent ON
                        parent.event_id = relates_to_id
                        AND parent.room_id = child.room_id
                    WHERE
                        %s
                        AND relation_type = ?
                    ORDER BY parent.event_id, child.topological_ordering DESC, child.stream_ordering DESC
                """
            else:
                # SQLite uses a simplified query which returns all entries for a
                # thread. The first result for each thread is chosen to and subsequent
                # results for a thread are ignored.
                sql = """
                    SELECT parent.event_id, child.event_id FROM events AS child
                    INNER JOIN event_relations USING (event_id)
                    INNER JOIN events AS parent ON
                        parent.event_id = relates_to_id
                        AND parent.room_id = child.room_id
                    WHERE
                        %s
                        AND relation_type = ?
                    ORDER BY child.topological_ordering DESC, child.stream_ordering DESC
                """

            clause, args = make_in_list_sql_clause(
                txn.database_engine, "relates_to_id", event_ids
            )
            args.append(RelationTypes.THREAD)

            txn.execute(sql % (clause,), args)
            latest_event_ids = {}
            for parent_event_id, child_event_id in txn:
                # Only consider the latest threaded reply (by topological ordering).
                if parent_event_id not in latest_event_ids:
                    latest_event_ids[parent_event_id] = child_event_id

            # If no threads were found, bail.
            if not latest_event_ids:
                return {}, latest_event_ids

            # Fetch the number of threaded replies.
            sql = """
                SELECT parent.event_id, COUNT(child.event_id) FROM events AS child
                INNER JOIN event_relations USING (event_id)
                INNER JOIN events AS parent ON
                    parent.event_id = relates_to_id
                    AND parent.room_id = child.room_id
                WHERE
                    %s
                    AND relation_type = ?
                GROUP BY parent.event_id
            """

            # Regenerate the arguments since only threads found above could
            # possibly have any replies.
            clause, args = make_in_list_sql_clause(
                txn.database_engine, "relates_to_id", latest_event_ids.keys()
            )
            args.append(RelationTypes.THREAD)

            txn.execute(sql % (clause,), args)
            counts = dict(cast(List[Tuple[str, int]], txn.fetchall()))

            return counts, latest_event_ids

        counts, latest_event_ids = await self.db_pool.runInteraction(
            "get_thread_summaries", _get_thread_summaries_txn
        )

        latest_events = await self.get_events(latest_event_ids.values())  # type: ignore[attr-defined]

        # Map to the event IDs to the thread summary.
        #
        # There might not be a summary due to there not being a thread or
        # due to the latest event not being known, either case is treated the same.
        summaries = {}
        for parent_event_id, latest_event_id in latest_event_ids.items():
            latest_event = latest_events.get(latest_event_id)

            summary = None
            if latest_event:
                summary = (counts[parent_event_id], latest_event)
            summaries[parent_event_id] = summary

        return summaries

    async def get_threaded_messages_per_user(
        self,
        event_ids: Collection[str],
        users: FrozenSet[str] = frozenset(),
    ) -> Dict[Tuple[str, str], int]:
        """Get the number of threaded replies for a set of users.

        This is used, in conjunction with get_thread_summaries, to calculate an
        accurate count of the replies to a thread by subtracting ignored users.

        Args:
            event_ids: The events to check for threaded replies.
            users: The user to calculate the count of their replies.

        Returns:
            A map of the (event_id, sender) to the count of their replies.
        """
        if not users:
            return {}

        # Fetch the number of threaded replies.
        sql = """
            SELECT parent.event_id, child.sender, COUNT(child.event_id) FROM events AS child
            INNER JOIN event_relations USING (event_id)
            INNER JOIN events AS parent ON
                parent.event_id = relates_to_id
                AND parent.room_id = child.room_id
            WHERE
                relation_type = ?
                AND %s
                AND %s
            GROUP BY parent.event_id, child.sender
        """

        def _get_threaded_messages_per_user_txn(
            txn: LoggingTransaction,
        ) -> Dict[Tuple[str, str], int]:
            users_sql, users_args = make_in_list_sql_clause(
                self.database_engine, "child.sender", users
            )
            events_clause, events_args = make_in_list_sql_clause(
                txn.database_engine, "relates_to_id", event_ids
            )

            txn.execute(
                sql % (users_sql, events_clause),
                [RelationTypes.THREAD] + users_args + events_args,
            )
            return {(row[0], row[1]): row[2] for row in txn}

        return await self.db_pool.runInteraction(
            "get_threaded_messages_per_user", _get_threaded_messages_per_user_txn
        )

    @cached()
    def get_thread_participated(self, event_id: str, user_id: str) -> bool:
        raise NotImplementedError()

    @cachedList(cached_method_name="get_thread_participated", list_name="event_ids")
    async def get_threads_participated(
        self, event_ids: Collection[str], user_id: str
    ) -> Mapping[str, bool]:
        """Get whether the requesting user participated in the given threads.

        This is separate from get_thread_summaries since that can be cached across
        all users while this value is specific to the requester.

        Args:
            event_ids: The thread related to these event IDs.
            user_id: The user requesting the summary.

        Returns:
            A map of event ID to a boolean which represents if the requesting
            user participated in that event's thread, otherwise false.
        """

        def _get_threads_participated_txn(txn: LoggingTransaction) -> Set[str]:
            # Fetch whether the requester has participated or not.
            sql = """
                SELECT DISTINCT relates_to_id
                FROM events AS child
                INNER JOIN event_relations USING (event_id)
                INNER JOIN events AS parent ON
                    parent.event_id = relates_to_id
                    AND parent.room_id = child.room_id
                WHERE
                    %s
                    AND relation_type = ?
                    AND child.sender = ?
            """

            clause, args = make_in_list_sql_clause(
                txn.database_engine, "relates_to_id", event_ids
            )
            args.extend([RelationTypes.THREAD, user_id])

            txn.execute(sql % (clause,), args)
            return {row[0] for row in txn.fetchall()}

        participated_threads = await self.db_pool.runInteraction(
            "get_threads_participated", _get_threads_participated_txn
        )

        return {event_id: event_id in participated_threads for event_id in event_ids}

    async def events_have_relations(
        self,
        parent_ids: List[str],
        relation_senders: Optional[List[str]],
        relation_types: Optional[List[str]],
    ) -> List[str]:
        """Check which events have a relationship from the given senders of the
        given types.

        Args:
            parent_ids: The events being annotated
            relation_senders: The relation senders to check.
            relation_types: The relation types to check.

        Returns:
            True if the event has at least one relationship from one of the given senders of the given type.
        """
        # If no restrictions are given then the event has the required relations.
        if not relation_senders and not relation_types:
            return parent_ids

        sql = """
            SELECT relates_to_id FROM event_relations
            INNER JOIN events USING (event_id)
            WHERE
                %s;
        """

        def _get_if_events_have_relations(txn: LoggingTransaction) -> List[str]:
            clauses: List[str] = []
            clause, args = make_in_list_sql_clause(
                txn.database_engine, "relates_to_id", parent_ids
            )
            clauses.append(clause)

            if relation_senders:
                clause, temp_args = make_in_list_sql_clause(
                    txn.database_engine, "sender", relation_senders
                )
                clauses.append(clause)
                args.extend(temp_args)
            if relation_types:
                clause, temp_args = make_in_list_sql_clause(
                    txn.database_engine, "relation_type", relation_types
                )
                clauses.append(clause)
                args.extend(temp_args)

            txn.execute(sql % " AND ".join(clauses), args)

            return [row[0] for row in txn]

        return await self.db_pool.runInteraction(
            "get_if_events_have_relations", _get_if_events_have_relations
        )

    async def has_user_annotated_event(
        self, parent_id: str, event_type: str, aggregation_key: str, sender: str
    ) -> bool:
        """Check if a user has already annotated an event with the same key
        (e.g. already liked an event).

        Args:
            parent_id: The event being annotated
            event_type: The event type of the annotation
            aggregation_key: The aggregation key of the annotation
            sender: The sender of the annotation

        Returns:
            True if the event is already annotated.
        """

        sql = """
            SELECT 1 FROM event_relations
            INNER JOIN events USING (event_id)
            WHERE
                relates_to_id = ?
                AND relation_type = ?
                AND type = ?
                AND sender = ?
                AND aggregation_key = ?
            LIMIT 1;
        """

        def _get_if_user_has_annotated_event(txn: LoggingTransaction) -> bool:
            txn.execute(
                sql,
                (
                    parent_id,
                    RelationTypes.ANNOTATION,
                    event_type,
                    sender,
                    aggregation_key,
                ),
            )

            return bool(txn.fetchone())

        return await self.db_pool.runInteraction(
            "get_if_user_has_annotated_event", _get_if_user_has_annotated_event
        )

    @cached(tree=True)
    async def get_threads(
        self,
        room_id: str,
        limit: int = 5,
        from_token: Optional[ThreadsNextBatch] = None,
    ) -> Tuple[Sequence[str], Optional[ThreadsNextBatch]]:
        """Get a list of thread IDs, ordered by topological ordering of their
        latest reply.

        Args:
            room_id: The room the event belongs to.
            limit: Only fetch the most recent `limit` threads.
            from_token: Fetch rows from a previous next_batch, or from the start if None.

        Returns:
            A tuple of:
                A list of thread root event IDs.

                The next_batch, if one exists.
        """
        # Generate the pagination clause, if necessary.
        #
        # Find any threads where the latest reply is equal / before the last
        # thread's topo ordering and earlier in stream ordering.
        pagination_clause = ""
        pagination_args: tuple = ()
        if from_token:
            pagination_clause = "AND topological_ordering <= ? AND stream_ordering < ?"
            pagination_args = (
                from_token.topological_ordering,
                from_token.stream_ordering,
            )

        sql = f"""
            SELECT thread_id, topological_ordering, stream_ordering
            FROM threads
            WHERE
                room_id = ?
                {pagination_clause}
            ORDER BY topological_ordering DESC, stream_ordering DESC
            LIMIT ?
        """

        def _get_threads_txn(
            txn: LoggingTransaction,
        ) -> Tuple[List[str], Optional[ThreadsNextBatch]]:
            txn.execute(sql, (room_id, *pagination_args, limit + 1))

            rows = cast(List[Tuple[str, int, int]], txn.fetchall())
            thread_ids = [r[0] for r in rows]

            # If there are more events, generate the next pagination key from the
            # last thread which will be returned.
            next_token = None
            if len(thread_ids) > limit:
                last_topo_id = rows[-2][1]
                last_stream_id = rows[-2][2]
                next_token = ThreadsNextBatch(last_topo_id, last_stream_id)

            return thread_ids[:limit], next_token

        return await self.db_pool.runInteraction("get_threads", _get_threads_txn)

    @cached()
    async def get_thread_id(self, event_id: str) -> str:
        """
        Get the thread ID for an event. This considers multi-level relations,
        e.g. an annotation to an event which is part of a thread.

        It only searches up the relations tree, i.e. it only searches for events
        which the given event is related to (and which those events are related
        to, etc.)

        Given the following DAG:

            A <---[m.thread]-- B <--[m.annotation]-- C
            ^
            |--[m.reference]-- D <--[m.annotation]-- E

        get_thread_id(X) considers events B and C as part of thread A.

        See also get_thread_id_for_receipts.

        Args:
            event_id: The event ID to fetch the thread ID for.

        Returns:
            The event ID of the root event in the thread, if this event is part
            of a thread. "main", otherwise.
        """

        # Recurse event relations up to the *root* event, then search that chain
        # of relations for a thread relation. If one is found, the root event is
        # returned.
        #
        # Note that this should only ever find 0 or 1 entries since it is invalid
        # for an event to have a thread relation to an event which also has a
        # relation.
        sql = """
            WITH RECURSIVE related_events AS (
                SELECT event_id, relates_to_id, relation_type, 0 AS depth
                FROM event_relations
                WHERE event_id = ?
                UNION SELECT e.event_id, e.relates_to_id, e.relation_type, depth + 1
                FROM event_relations e
                INNER JOIN related_events r ON r.relates_to_id = e.event_id
                WHERE depth <= 3
            )
            SELECT relates_to_id FROM related_events
            WHERE relation_type = 'm.thread'
            ORDER BY depth DESC
            LIMIT 1;
        """

        def _get_thread_id(txn: LoggingTransaction) -> str:
            txn.execute(sql, (event_id,))
            row = txn.fetchone()
            if row:
                return row[0]

            # If no thread was found, it is part of the main timeline.
            return MAIN_TIMELINE

        return await self.db_pool.runInteraction("get_thread_id", _get_thread_id)

    @cached()
    async def get_thread_id_for_receipts(self, event_id: str) -> str:
        """
        Get the thread ID for an event by traversing to the top-most related event
        and confirming any children events form a thread.

        Given the following DAG:

            A <---[m.thread]-- B <--[m.annotation]-- C
            ^
            |--[m.reference]-- D <--[m.annotation]-- E

        get_thread_id_for_receipts(X) considers events A, B, C, D, and E as part
        of thread A.

        See also get_thread_id.

        Args:
            event_id: The event ID to fetch the thread ID for.

        Returns:
            The event ID of the root event in the thread, if this event is part
            of a thread. "main", otherwise.
        """

        # Recurse event relations up to the *root* event, then search for any events
        # related to that root node for a thread relation. If one is found, the
        # root event is returned.
        #
        # Note that there cannot be thread relations in the middle of the chain since
        # it is invalid for an event to have a thread relation to an event which also
        # has a relation.
        sql = """
        SELECT relates_to_id FROM event_relations WHERE relates_to_id = COALESCE((
            WITH RECURSIVE related_events AS (
                SELECT event_id, relates_to_id, relation_type, 0 AS depth
                FROM event_relations
                WHERE event_id = ?
                UNION SELECT e.event_id, e.relates_to_id, e.relation_type, depth + 1
                FROM event_relations e
                INNER JOIN related_events r ON r.relates_to_id = e.event_id
                WHERE depth <= 3
            )
            SELECT relates_to_id FROM related_events
            ORDER BY depth DESC
            LIMIT 1
        ), ?) AND relation_type = 'm.thread' LIMIT 1;
        """

        def _get_related_thread_id(txn: LoggingTransaction) -> str:
            txn.execute(sql, (event_id, event_id))
            row = txn.fetchone()
            if row:
                return row[0]

            # If no thread was found, it is part of the main timeline.
            return MAIN_TIMELINE

        return await self.db_pool.runInteraction(
            "get_related_thread_id", _get_related_thread_id
        )


class RelationsStore(RelationsWorkerStore):
    pass
