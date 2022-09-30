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
    Collection,
    Dict,
    FrozenSet,
    Iterable,
    List,
    Optional,
    Set,
    Tuple,
    Union,
    cast,
)

import attr

from synapse.api.constants import RelationTypes
from synapse.events import EventBase
from synapse.storage._base import SQLBaseStore
from synapse.storage.database import LoggingTransaction, make_in_list_sql_clause
from synapse.storage.databases.main.stream import generate_pagination_where_clause
from synapse.storage.engines import PostgresEngine
from synapse.types import JsonDict, RoomStreamToken, StreamKeyType, StreamToken
from synapse.util.caches.descriptors import cached, cachedList

logger = logging.getLogger(__name__)


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
    topological_ordering: Optional[int]
    stream_ordering: int


class RelationsWorkerStore(SQLBaseStore):
    @cached(uncached_args=("event",), tree=True)
    async def get_relations_for_event(
        self,
        event_id: str,
        event: EventBase,
        room_id: str,
        relation_type: Optional[str] = None,
        event_type: Optional[str] = None,
        limit: int = 5,
        direction: str = "b",
        from_token: Optional[StreamToken] = None,
        to_token: Optional[StreamToken] = None,
    ) -> Tuple[List[_RelatedEvent], Optional[StreamToken]]:
        """Get a list of relations for an event, ordered by topological ordering.

        Args:
            event_id: Fetch events that relate to this event ID.
            event: The matching EventBase to event_id.
            room_id: The room the event belongs to.
            relation_type: Only fetch events with this relation type, if given.
            event_type: Only fetch events with this event type, if given.
            limit: Only fetch the most recent `limit` events.
            direction: Whether to fetch the most recent first (`"b"`) or the
                oldest first (`"f"`).
            from_token: Fetch rows from the given token, or from the start if None.
            to_token: Fetch rows up to the given token, or up to the end if None.

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

        where_clause = ["relates_to_id = ?", "room_id = ?"]
        where_args: List[Union[str, int]] = [event.event_id, room_id]
        is_redacted = event.internal_metadata.is_redacted()

        if relation_type is not None:
            where_clause.append("relation_type = ?")
            where_args.append(relation_type)

        if event_type is not None:
            where_clause.append("type = ?")
            where_args.append(event_type)

        pagination_clause = generate_pagination_where_clause(
            direction=direction,
            column_names=("topological_ordering", "stream_ordering"),
            from_token=from_token.room_key.as_historical_tuple()
            if from_token
            else None,
            to_token=to_token.room_key.as_historical_tuple() if to_token else None,
            engine=self.database_engine,
        )

        if pagination_clause:
            where_clause.append(pagination_clause)

        if direction == "b":
            order = "DESC"
        else:
            order = "ASC"

        sql = """
            SELECT event_id, relation_type, sender, topological_ordering, stream_ordering
            FROM event_relations
            INNER JOIN events USING (event_id)
            WHERE %s
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
            txn.execute(sql, where_args + [limit + 1])

            events = []
            for event_id, relation_type, sender, topo_ordering, stream_ordering in txn:
                # Do not include edits for redacted events as they leak event
                # content.
                if not is_redacted or relation_type != RelationTypes.REPLACE:
                    events.append(
                        _RelatedEvent(event_id, sender, topo_ordering, stream_ordering)
                    )

            # If there are more events, generate the next pagination key from the
            # last event returned.
            next_token = None
            if len(events) > limit:
                # Instead of using the last row (which tells us there is more
                # data), use the last row to be returned.
                events = events[:limit]

                topo = events[-1].topological_ordering
                token = events[-1].stream_ordering
                if direction == "b":
                    # Tokens are positions between events.
                    # This token points *after* the last event in the chunk.
                    # We need it to point to the event before it in the chunk
                    # when we are going backwards so we subtract one from the
                    # stream part.
                    token -= 1
                next_key = RoomStreamToken(topo, token)

                if from_token:
                    next_token = from_token.copy_and_replace(
                        StreamKeyType.ROOM, next_key
                    )
                else:
                    next_token = StreamToken(
                        room_key=next_key,
                        presence_key=0,
                        typing_key=0,
                        receipt_key=0,
                        account_data_key=0,
                        push_rules_key=0,
                        to_device_key=0,
                        device_list_key=0,
                        groups_key=0,
                    )

            return events[:limit], next_token

        return await self.db_pool.runInteraction(
            "get_recent_references_for_event", _get_recent_references_for_event_txn
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

    @cached(tree=True)
    async def get_aggregation_groups_for_event(
        self, event_id: str, room_id: str, limit: int = 5
    ) -> List[JsonDict]:
        """Get a list of annotations on the event, grouped by event type and
        aggregation key, sorted by count.

        This is used e.g. to get the what and how many reactions have happend
        on an event.

        Args:
            event_id: Fetch events that relate to this event ID.
            room_id: The room the event belongs to.
            limit: Only fetch the `limit` groups.

        Returns:
            List of groups of annotations that match. Each row is a dict with
            `type`, `key` and `count` fields.
        """

        args = [
            event_id,
            room_id,
            RelationTypes.ANNOTATION,
            limit,
        ]

        sql = """
            SELECT type, aggregation_key, COUNT(DISTINCT sender)
            FROM event_relations
            INNER JOIN events USING (event_id)
            WHERE relates_to_id = ? AND room_id = ? AND relation_type = ?
            GROUP BY relation_type, type, aggregation_key
            ORDER BY COUNT(*) DESC
            LIMIT ?
        """

        def _get_aggregation_groups_for_event_txn(
            txn: LoggingTransaction,
        ) -> List[JsonDict]:
            txn.execute(sql, args)

            return [{"type": row[0], "key": row[1], "count": row[2]} for row in txn]

        return await self.db_pool.runInteraction(
            "get_aggregation_groups_for_event", _get_aggregation_groups_for_event_txn
        )

    async def get_aggregation_groups_for_users(
        self,
        event_id: str,
        room_id: str,
        limit: int,
        users: FrozenSet[str] = frozenset(),
    ) -> Dict[Tuple[str, str], int]:
        """Fetch the partial aggregations for an event for specific users.

        This is used, in conjunction with get_aggregation_groups_for_event, to
        remove information from the results for ignored users.

        Args:
            event_id: Fetch events that relate to this event ID.
            room_id: The room the event belongs to.
            limit: Only fetch the `limit` groups.
            users: The users to fetch information for.

        Returns:
            A map of (event type, aggregation key) to a count of users.
        """

        if not users:
            return {}

        args: List[Union[str, int]] = [
            event_id,
            room_id,
            RelationTypes.ANNOTATION,
        ]

        users_sql, users_args = make_in_list_sql_clause(
            self.database_engine, "sender", users
        )
        args.extend(users_args)

        sql = f"""
            SELECT type, aggregation_key, COUNT(DISTINCT sender)
            FROM event_relations
            INNER JOIN events USING (event_id)
            WHERE relates_to_id = ? AND room_id = ? AND relation_type = ? AND {users_sql}
            GROUP BY relation_type, type, aggregation_key
            ORDER BY COUNT(*) DESC
            LIMIT ?
        """

        def _get_aggregation_groups_for_users_txn(
            txn: LoggingTransaction,
        ) -> Dict[Tuple[str, str], int]:
            txn.execute(sql, args + [limit])

            return {(row[0], row[1]): row[2] for row in txn}

        return await self.db_pool.runInteraction(
            "get_aggregation_groups_for_users", _get_aggregation_groups_for_users_txn
        )

    @cached()
    def get_applicable_edit(self, event_id: str) -> Optional[EventBase]:
        raise NotImplementedError()

    @cachedList(cached_method_name="get_applicable_edit", list_name="event_ids")
    async def get_applicable_edits(
        self, event_ids: Collection[str]
    ) -> Dict[str, Optional[EventBase]]:
        """Get the most recent edit (if any) that has happened for the given
        events.

        Correctly handles checking whether edits were allowed to happen.

        Args:
            event_ids: The original event IDs

        Returns:
            A map of the most recent edit for each event. If there are no edits,
            the event will map to None.
        """

        # We only allow edits for `m.room.message` events that have the same sender
        # and event type. We can't assert these things during regular event auth so
        # we have to do the checks post hoc.

        # Fetches latest edit that has the same type and sender as the
        # original, and is an `m.room.message`.
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
                    AND edit.type = 'm.room.message'
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
                    AND edit.type = 'm.room.message'
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

    @cached()
    def get_thread_summary(self, event_id: str) -> Optional[Tuple[int, EventBase]]:
        raise NotImplementedError()

    @cachedList(cached_method_name="get_thread_summary", list_name="event_ids")
    async def get_thread_summaries(
        self, event_ids: Collection[str]
    ) -> Dict[str, Optional[Tuple[int, EventBase]]]:
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
    ) -> Dict[str, bool]:
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

    @cached(iterable=True)
    async def get_mutual_event_relations_for_rel_type(
        self, event_id: str, relation_type: str
    ) -> Set[Tuple[str, str]]:
        raise NotImplementedError()

    @cachedList(
        cached_method_name="get_mutual_event_relations_for_rel_type",
        list_name="relation_types",
    )
    async def get_mutual_event_relations(
        self, event_id: str, relation_types: Collection[str]
    ) -> Dict[str, Set[Tuple[str, str]]]:
        """
        Fetch event metadata for events which related to the same event as the given event.

        If the given event has no relation information, returns an empty dictionary.

        Args:
            event_id: The event ID which is targeted by relations.
            relation_types: The relation types to check for mutual relations.

        Returns:
            A dictionary of relation type to:
                A set of tuples of:
                    The sender
                    The event type
        """
        rel_type_sql, rel_type_args = make_in_list_sql_clause(
            self.database_engine, "relation_type", relation_types
        )

        sql = f"""
            SELECT DISTINCT relation_type, sender, type FROM event_relations
            INNER JOIN events USING (event_id)
            WHERE relates_to_id = ? AND {rel_type_sql}
        """

        def _get_event_relations(
            txn: LoggingTransaction,
        ) -> Dict[str, Set[Tuple[str, str]]]:
            txn.execute(sql, [event_id] + rel_type_args)
            result: Dict[str, Set[Tuple[str, str]]] = {
                rel_type: set() for rel_type in relation_types
            }
            for rel_type, sender, type in txn.fetchall():
                result[rel_type].add((sender, type))
            return result

        return await self.db_pool.runInteraction(
            "get_event_relations", _get_event_relations
        )


class RelationsStore(RelationsWorkerStore):
    pass
