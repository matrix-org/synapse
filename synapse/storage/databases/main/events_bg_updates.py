# -*- coding: utf-8 -*-
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

import logging
from typing import Dict, List, Optional, Tuple

import attr

from synapse.api.constants import EventContentFields
from synapse.api.room_versions import KNOWN_ROOM_VERSIONS
from synapse.events import make_event_from_dict
from synapse.storage._base import SQLBaseStore, db_to_json, make_in_list_sql_clause
from synapse.storage.database import DatabasePool, make_tuple_comparison_clause
from synapse.storage.databases.main.events import PersistEventsStore
from synapse.storage.types import Cursor
from synapse.types import JsonDict

logger = logging.getLogger(__name__)


@attr.s(slots=True, frozen=True)
class _CalculateChainCover:
    """Return value for _calculate_chain_cover_txn."""

    # The last room_id/depth/stream processed.
    room_id = attr.ib(type=str)
    depth = attr.ib(type=int)
    stream = attr.ib(type=int)

    # Number of rows processed
    processed_count = attr.ib(type=int)

    # Map from room_id to last depth/stream processed for each room that we have
    # processed all events for (i.e. the rooms we can flip the
    # `has_auth_chain_index` for)
    finished_room_map = attr.ib(type=Dict[str, Tuple[int, int]])


class EventsBackgroundUpdatesStore(SQLBaseStore):

    EVENT_ORIGIN_SERVER_TS_NAME = "event_origin_server_ts"
    EVENT_FIELDS_SENDER_URL_UPDATE_NAME = "event_fields_sender_url"
    DELETE_SOFT_FAILED_EXTREMITIES = "delete_soft_failed_extremities"

    def __init__(self, database: DatabasePool, db_conn, hs):
        super().__init__(database, db_conn, hs)

        self.db_pool.updates.register_background_update_handler(
            self.EVENT_ORIGIN_SERVER_TS_NAME, self._background_reindex_origin_server_ts
        )
        self.db_pool.updates.register_background_update_handler(
            self.EVENT_FIELDS_SENDER_URL_UPDATE_NAME,
            self._background_reindex_fields_sender,
        )

        self.db_pool.updates.register_background_index_update(
            "event_contains_url_index",
            index_name="event_contains_url_index",
            table="events",
            columns=["room_id", "topological_ordering", "stream_ordering"],
            where_clause="contains_url = true AND outlier = false",
        )

        # an event_id index on event_search is useful for the purge_history
        # api. Plus it means we get to enforce some integrity with a UNIQUE
        # clause
        self.db_pool.updates.register_background_index_update(
            "event_search_event_id_idx",
            index_name="event_search_event_id_idx",
            table="event_search",
            columns=["event_id"],
            unique=True,
            psql_only=True,
        )

        self.db_pool.updates.register_background_update_handler(
            self.DELETE_SOFT_FAILED_EXTREMITIES, self._cleanup_extremities_bg_update
        )

        self.db_pool.updates.register_background_update_handler(
            "redactions_received_ts", self._redactions_received_ts
        )

        # This index gets deleted in `event_fix_redactions_bytes` update
        self.db_pool.updates.register_background_index_update(
            "event_fix_redactions_bytes_create_index",
            index_name="redactions_censored_redacts",
            table="redactions",
            columns=["redacts"],
            where_clause="have_censored",
        )

        self.db_pool.updates.register_background_update_handler(
            "event_fix_redactions_bytes", self._event_fix_redactions_bytes
        )

        self.db_pool.updates.register_background_update_handler(
            "event_store_labels", self._event_store_labels
        )

        self.db_pool.updates.register_background_index_update(
            "redactions_have_censored_ts_idx",
            index_name="redactions_have_censored_ts",
            table="redactions",
            columns=["received_ts"],
            where_clause="NOT have_censored",
        )

        self.db_pool.updates.register_background_index_update(
            "users_have_local_media",
            index_name="users_have_local_media",
            table="local_media_repository",
            columns=["user_id", "created_ts"],
        )

        self.db_pool.updates.register_background_update_handler(
            "rejected_events_metadata",
            self._rejected_events_metadata,
        )

        self.db_pool.updates.register_background_update_handler(
            "chain_cover",
            self._chain_cover_index,
        )

    async def _background_reindex_fields_sender(self, progress, batch_size):
        target_min_stream_id = progress["target_min_stream_id_inclusive"]
        max_stream_id = progress["max_stream_id_exclusive"]
        rows_inserted = progress.get("rows_inserted", 0)

        def reindex_txn(txn):
            sql = (
                "SELECT stream_ordering, event_id, json FROM events"
                " INNER JOIN event_json USING (event_id)"
                " WHERE ? <= stream_ordering AND stream_ordering < ?"
                " ORDER BY stream_ordering DESC"
                " LIMIT ?"
            )

            txn.execute(sql, (target_min_stream_id, max_stream_id, batch_size))

            rows = txn.fetchall()
            if not rows:
                return 0

            min_stream_id = rows[-1][0]

            update_rows = []
            for row in rows:
                try:
                    event_id = row[1]
                    event_json = db_to_json(row[2])
                    sender = event_json["sender"]
                    content = event_json["content"]

                    contains_url = "url" in content
                    if contains_url:
                        contains_url &= isinstance(content["url"], str)
                except (KeyError, AttributeError):
                    # If the event is missing a necessary field then
                    # skip over it.
                    continue

                update_rows.append((sender, contains_url, event_id))

            sql = "UPDATE events SET sender = ?, contains_url = ? WHERE event_id = ?"

            txn.execute_batch(sql, update_rows)

            progress = {
                "target_min_stream_id_inclusive": target_min_stream_id,
                "max_stream_id_exclusive": min_stream_id,
                "rows_inserted": rows_inserted + len(rows),
            }

            self.db_pool.updates._background_update_progress_txn(
                txn, self.EVENT_FIELDS_SENDER_URL_UPDATE_NAME, progress
            )

            return len(rows)

        result = await self.db_pool.runInteraction(
            self.EVENT_FIELDS_SENDER_URL_UPDATE_NAME, reindex_txn
        )

        if not result:
            await self.db_pool.updates._end_background_update(
                self.EVENT_FIELDS_SENDER_URL_UPDATE_NAME
            )

        return result

    async def _background_reindex_origin_server_ts(self, progress, batch_size):
        target_min_stream_id = progress["target_min_stream_id_inclusive"]
        max_stream_id = progress["max_stream_id_exclusive"]
        rows_inserted = progress.get("rows_inserted", 0)

        def reindex_search_txn(txn):
            sql = (
                "SELECT stream_ordering, event_id FROM events"
                " WHERE ? <= stream_ordering AND stream_ordering < ?"
                " ORDER BY stream_ordering DESC"
                " LIMIT ?"
            )

            txn.execute(sql, (target_min_stream_id, max_stream_id, batch_size))

            rows = txn.fetchall()
            if not rows:
                return 0

            min_stream_id = rows[-1][0]
            event_ids = [row[1] for row in rows]

            rows_to_update = []

            chunks = [event_ids[i : i + 100] for i in range(0, len(event_ids), 100)]
            for chunk in chunks:
                ev_rows = self.db_pool.simple_select_many_txn(
                    txn,
                    table="event_json",
                    column="event_id",
                    iterable=chunk,
                    retcols=["event_id", "json"],
                    keyvalues={},
                )

                for row in ev_rows:
                    event_id = row["event_id"]
                    event_json = db_to_json(row["json"])
                    try:
                        origin_server_ts = event_json["origin_server_ts"]
                    except (KeyError, AttributeError):
                        # If the event is missing a necessary field then
                        # skip over it.
                        continue

                    rows_to_update.append((origin_server_ts, event_id))

            sql = "UPDATE events SET origin_server_ts = ? WHERE event_id = ?"

            txn.execute_batch(sql, rows_to_update)

            progress = {
                "target_min_stream_id_inclusive": target_min_stream_id,
                "max_stream_id_exclusive": min_stream_id,
                "rows_inserted": rows_inserted + len(rows_to_update),
            }

            self.db_pool.updates._background_update_progress_txn(
                txn, self.EVENT_ORIGIN_SERVER_TS_NAME, progress
            )

            return len(rows_to_update)

        result = await self.db_pool.runInteraction(
            self.EVENT_ORIGIN_SERVER_TS_NAME, reindex_search_txn
        )

        if not result:
            await self.db_pool.updates._end_background_update(
                self.EVENT_ORIGIN_SERVER_TS_NAME
            )

        return result

    async def _cleanup_extremities_bg_update(self, progress, batch_size):
        """Background update to clean out extremities that should have been
        deleted previously.

        Mainly used to deal with the aftermath of #5269.
        """

        # This works by first copying all existing forward extremities into the
        # `_extremities_to_check` table at start up, and then checking each
        # event in that table whether we have any descendants that are not
        # soft-failed/rejected. If that is the case then we delete that event
        # from the forward extremities table.
        #
        # For efficiency, we do this in batches by recursively pulling out all
        # descendants of a batch until we find the non soft-failed/rejected
        # events, i.e. the set of descendants whose chain of prev events back
        # to the batch of extremities are all soft-failed or rejected.
        # Typically, we won't find any such events as extremities will rarely
        # have any descendants, but if they do then we should delete those
        # extremities.

        def _cleanup_extremities_bg_update_txn(txn):
            # The set of extremity event IDs that we're checking this round
            original_set = set()

            # A dict[str, set[str]] of event ID to their prev events.
            graph = {}

            # The set of descendants of the original set that are not rejected
            # nor soft-failed. Ancestors of these events should be removed
            # from the forward extremities table.
            non_rejected_leaves = set()

            # Set of event IDs that have been soft failed, and for which we
            # should check if they have descendants which haven't been soft
            # failed.
            soft_failed_events_to_lookup = set()

            # First, we get `batch_size` events from the table, pulling out
            # their successor events, if any, and the successor events'
            # rejection status.
            txn.execute(
                """SELECT prev_event_id, event_id, internal_metadata,
                    rejections.event_id IS NOT NULL, events.outlier
                FROM (
                    SELECT event_id AS prev_event_id
                    FROM _extremities_to_check
                    LIMIT ?
                ) AS f
                LEFT JOIN event_edges USING (prev_event_id)
                LEFT JOIN events USING (event_id)
                LEFT JOIN event_json USING (event_id)
                LEFT JOIN rejections USING (event_id)
                """,
                (batch_size,),
            )

            for prev_event_id, event_id, metadata, rejected, outlier in txn:
                original_set.add(prev_event_id)

                if not event_id or outlier:
                    # Common case where the forward extremity doesn't have any
                    # descendants.
                    continue

                graph.setdefault(event_id, set()).add(prev_event_id)

                soft_failed = False
                if metadata:
                    soft_failed = db_to_json(metadata).get("soft_failed")

                if soft_failed or rejected:
                    soft_failed_events_to_lookup.add(event_id)
                else:
                    non_rejected_leaves.add(event_id)

            # Now we recursively check all the soft-failed descendants we
            # found above in the same way, until we have nothing left to
            # check.
            while soft_failed_events_to_lookup:
                # We only want to do 100 at a time, so we split given list
                # into two.
                batch = list(soft_failed_events_to_lookup)
                to_check, to_defer = batch[:100], batch[100:]
                soft_failed_events_to_lookup = set(to_defer)

                sql = """SELECT prev_event_id, event_id, internal_metadata,
                    rejections.event_id IS NOT NULL
                    FROM event_edges
                    INNER JOIN events USING (event_id)
                    INNER JOIN event_json USING (event_id)
                    LEFT JOIN rejections USING (event_id)
                    WHERE
                        NOT events.outlier
                        AND
                """
                clause, args = make_in_list_sql_clause(
                    self.database_engine, "prev_event_id", to_check
                )
                txn.execute(sql + clause, list(args))

                for prev_event_id, event_id, metadata, rejected in txn:
                    if event_id in graph:
                        # Already handled this event previously, but we still
                        # want to record the edge.
                        graph[event_id].add(prev_event_id)
                        continue

                    graph[event_id] = {prev_event_id}

                    soft_failed = db_to_json(metadata).get("soft_failed")
                    if soft_failed or rejected:
                        soft_failed_events_to_lookup.add(event_id)
                    else:
                        non_rejected_leaves.add(event_id)

            # We have a set of non-soft-failed descendants, so we recurse up
            # the graph to find all ancestors and add them to the set of event
            # IDs that we can delete from forward extremities table.
            to_delete = set()
            while non_rejected_leaves:
                event_id = non_rejected_leaves.pop()
                prev_event_ids = graph.get(event_id, set())
                non_rejected_leaves.update(prev_event_ids)
                to_delete.update(prev_event_ids)

            to_delete.intersection_update(original_set)

            deleted = self.db_pool.simple_delete_many_txn(
                txn=txn,
                table="event_forward_extremities",
                column="event_id",
                iterable=to_delete,
                keyvalues={},
            )

            logger.info(
                "Deleted %d forward extremities of %d checked, to clean up #5269",
                deleted,
                len(original_set),
            )

            if deleted:
                # We now need to invalidate the caches of these rooms
                rows = self.db_pool.simple_select_many_txn(
                    txn,
                    table="events",
                    column="event_id",
                    iterable=to_delete,
                    keyvalues={},
                    retcols=("room_id",),
                )
                room_ids = {row["room_id"] for row in rows}
                for room_id in room_ids:
                    txn.call_after(
                        self.get_latest_event_ids_in_room.invalidate, (room_id,)
                    )

            self.db_pool.simple_delete_many_txn(
                txn=txn,
                table="_extremities_to_check",
                column="event_id",
                iterable=original_set,
                keyvalues={},
            )

            return len(original_set)

        num_handled = await self.db_pool.runInteraction(
            "_cleanup_extremities_bg_update", _cleanup_extremities_bg_update_txn
        )

        if not num_handled:
            await self.db_pool.updates._end_background_update(
                self.DELETE_SOFT_FAILED_EXTREMITIES
            )

            def _drop_table_txn(txn):
                txn.execute("DROP TABLE _extremities_to_check")

            await self.db_pool.runInteraction(
                "_cleanup_extremities_bg_update_drop_table", _drop_table_txn
            )

        return num_handled

    async def _redactions_received_ts(self, progress, batch_size):
        """Handles filling out the `received_ts` column in redactions."""
        last_event_id = progress.get("last_event_id", "")

        def _redactions_received_ts_txn(txn):
            # Fetch the set of event IDs that we want to update
            sql = """
                SELECT event_id FROM redactions
                WHERE event_id > ?
                ORDER BY event_id ASC
                LIMIT ?
            """

            txn.execute(sql, (last_event_id, batch_size))

            rows = txn.fetchall()
            if not rows:
                return 0

            (upper_event_id,) = rows[-1]

            # Update the redactions with the received_ts.
            #
            # Note: Not all events have an associated received_ts, so we
            # fallback to using origin_server_ts. If we for some reason don't
            # have an origin_server_ts, lets just use the current timestamp.
            #
            # We don't want to leave it null, as then we'll never try and
            # censor those redactions.
            sql = """
                UPDATE redactions
                SET received_ts = (
                    SELECT COALESCE(received_ts, origin_server_ts, ?) FROM events
                    WHERE events.event_id = redactions.event_id
                )
                WHERE ? <= event_id AND event_id <= ?
            """

            txn.execute(sql, (self._clock.time_msec(), last_event_id, upper_event_id))

            self.db_pool.updates._background_update_progress_txn(
                txn, "redactions_received_ts", {"last_event_id": upper_event_id}
            )

            return len(rows)

        count = await self.db_pool.runInteraction(
            "_redactions_received_ts", _redactions_received_ts_txn
        )

        if not count:
            await self.db_pool.updates._end_background_update("redactions_received_ts")

        return count

    async def _event_fix_redactions_bytes(self, progress, batch_size):
        """Undoes hex encoded censored redacted event JSON."""

        def _event_fix_redactions_bytes_txn(txn):
            # This update is quite fast due to new index.
            txn.execute(
                """
                UPDATE event_json
                SET
                    json = convert_from(json::bytea, 'utf8')
                FROM redactions
                WHERE
                    redactions.have_censored
                    AND event_json.event_id = redactions.redacts
                    AND json NOT LIKE '{%';
                """
            )

            txn.execute("DROP INDEX redactions_censored_redacts")

        await self.db_pool.runInteraction(
            "_event_fix_redactions_bytes", _event_fix_redactions_bytes_txn
        )

        await self.db_pool.updates._end_background_update("event_fix_redactions_bytes")

        return 1

    async def _event_store_labels(self, progress, batch_size):
        """Background update handler which will store labels for existing events."""
        last_event_id = progress.get("last_event_id", "")

        def _event_store_labels_txn(txn):
            txn.execute(
                """
                SELECT event_id, json FROM event_json
                LEFT JOIN event_labels USING (event_id)
                WHERE event_id > ? AND label IS NULL
                ORDER BY event_id LIMIT ?
                """,
                (last_event_id, batch_size),
            )

            results = list(txn)

            nbrows = 0
            last_row_event_id = ""
            for (event_id, event_json_raw) in results:
                try:
                    event_json = db_to_json(event_json_raw)

                    self.db_pool.simple_insert_many_txn(
                        txn=txn,
                        table="event_labels",
                        values=[
                            {
                                "event_id": event_id,
                                "label": label,
                                "room_id": event_json["room_id"],
                                "topological_ordering": event_json["depth"],
                            }
                            for label in event_json["content"].get(
                                EventContentFields.LABELS, []
                            )
                            if isinstance(label, str)
                        ],
                    )
                except Exception as e:
                    logger.warning(
                        "Unable to load event %s (no labels will be imported): %s",
                        event_id,
                        e,
                    )

                nbrows += 1
                last_row_event_id = event_id

            self.db_pool.updates._background_update_progress_txn(
                txn, "event_store_labels", {"last_event_id": last_row_event_id}
            )

            return nbrows

        num_rows = await self.db_pool.runInteraction(
            desc="event_store_labels", func=_event_store_labels_txn
        )

        if not num_rows:
            await self.db_pool.updates._end_background_update("event_store_labels")

        return num_rows

    async def _rejected_events_metadata(self, progress: dict, batch_size: int) -> int:
        """Adds rejected events to the `state_events` and `event_auth` metadata
        tables.
        """

        last_event_id = progress.get("last_event_id", "")

        def get_rejected_events(
            txn: Cursor,
        ) -> List[Tuple[str, str, JsonDict, bool, bool]]:
            # Fetch rejected event json, their room version and whether we have
            # inserted them into the state_events or auth_events tables.
            #
            # Note we can assume that events that don't have a corresponding
            # room version are V1 rooms.
            sql = """
                SELECT DISTINCT
                    event_id,
                    COALESCE(room_version, '1'),
                    json,
                    state_events.event_id IS NOT NULL,
                    event_auth.event_id IS NOT NULL
                FROM rejections
                INNER JOIN event_json USING (event_id)
                LEFT JOIN rooms USING (room_id)
                LEFT JOIN state_events USING (event_id)
                LEFT JOIN event_auth USING (event_id)
                WHERE event_id > ?
                ORDER BY event_id
                LIMIT ?
            """

            txn.execute(
                sql,
                (
                    last_event_id,
                    batch_size,
                ),
            )

            return [(row[0], row[1], db_to_json(row[2]), row[3], row[4]) for row in txn]  # type: ignore

        results = await self.db_pool.runInteraction(
            desc="_rejected_events_metadata_get", func=get_rejected_events
        )

        if not results:
            await self.db_pool.updates._end_background_update(
                "rejected_events_metadata"
            )
            return 0

        state_events = []
        auth_events = []
        for event_id, room_version, event_json, has_state, has_event_auth in results:
            last_event_id = event_id

            if has_state and has_event_auth:
                continue

            room_version_obj = KNOWN_ROOM_VERSIONS.get(room_version)
            if not room_version_obj:
                # We no longer support this room version, so we just ignore the
                # events entirely.
                logger.info(
                    "Ignoring event with unknown room version %r: %r",
                    room_version,
                    event_id,
                )
                continue

            event = make_event_from_dict(event_json, room_version_obj)

            if not event.is_state():
                continue

            if not has_state:
                state_events.append(
                    {
                        "event_id": event.event_id,
                        "room_id": event.room_id,
                        "type": event.type,
                        "state_key": event.state_key,
                    }
                )

            if not has_event_auth:
                for auth_id in event.auth_event_ids():
                    auth_events.append(
                        {
                            "room_id": event.room_id,
                            "event_id": event.event_id,
                            "auth_id": auth_id,
                        }
                    )

        if state_events:
            await self.db_pool.simple_insert_many(
                table="state_events",
                values=state_events,
                desc="_rejected_events_metadata_state_events",
            )

        if auth_events:
            await self.db_pool.simple_insert_many(
                table="event_auth",
                values=auth_events,
                desc="_rejected_events_metadata_event_auth",
            )

        await self.db_pool.updates._background_update_progress(
            "rejected_events_metadata", {"last_event_id": last_event_id}
        )

        if len(results) < batch_size:
            await self.db_pool.updates._end_background_update(
                "rejected_events_metadata"
            )

        return len(results)

    async def _chain_cover_index(self, progress: dict, batch_size: int) -> int:
        """A background updates that iterates over all rooms and generates the
        chain cover index for them.
        """

        current_room_id = progress.get("current_room_id", "")

        # Where we've processed up to in the room, defaults to the start of the
        # room.
        last_depth = progress.get("last_depth", -1)
        last_stream = progress.get("last_stream", -1)

        result = await self.db_pool.runInteraction(
            "_chain_cover_index",
            self._calculate_chain_cover_txn,
            current_room_id,
            last_depth,
            last_stream,
            batch_size,
            single_room=False,
        )

        finished = result.processed_count == 0

        total_rows_processed = result.processed_count
        current_room_id = result.room_id
        last_depth = result.depth
        last_stream = result.stream

        for room_id, (depth, stream) in result.finished_room_map.items():
            # If we've done all the events in the room we flip the
            # `has_auth_chain_index` in the DB. Note that its possible for
            # further events to be persisted between the above and setting the
            # flag without having the chain cover calculated for them. This is
            # fine as a) the code gracefully handles these cases and b) we'll
            # calculate them below.

            await self.db_pool.simple_update(
                table="rooms",
                keyvalues={"room_id": room_id},
                updatevalues={"has_auth_chain_index": True},
                desc="_chain_cover_index",
            )

            # Handle any events that might have raced with us flipping the
            # bit above.
            result = await self.db_pool.runInteraction(
                "_chain_cover_index",
                self._calculate_chain_cover_txn,
                room_id,
                depth,
                stream,
                batch_size=None,
                single_room=True,
            )

            total_rows_processed += result.processed_count

        if finished:
            await self.db_pool.updates._end_background_update("chain_cover")
            return total_rows_processed

        await self.db_pool.updates._background_update_progress(
            "chain_cover",
            {
                "current_room_id": current_room_id,
                "last_depth": last_depth,
                "last_stream": last_stream,
            },
        )

        return total_rows_processed

    def _calculate_chain_cover_txn(
        self,
        txn: Cursor,
        last_room_id: str,
        last_depth: int,
        last_stream: int,
        batch_size: Optional[int],
        single_room: bool,
    ) -> _CalculateChainCover:
        """Calculate the chain cover for `batch_size` events, ordered by
        `(room_id, depth, stream)`.

        Args:
            txn,
            last_room_id, last_depth, last_stream: The `(room_id, depth, stream)`
                tuple to fetch results after.
            batch_size: The maximum number of events to process. If None then
                no limit.
            single_room: Whether to calculate the index for just the given
                room.
        """

        # Get the next set of events in the room (that we haven't already
        # computed chain cover for). We do this in topological order.

        # We want to do a `(topological_ordering, stream_ordering) > (?,?)`
        # comparison, but that is not supported on older SQLite versions
        tuple_clause, tuple_args = make_tuple_comparison_clause(
            self.database_engine,
            [
                ("events.room_id", last_room_id),
                ("topological_ordering", last_depth),
                ("stream_ordering", last_stream),
            ],
        )

        extra_clause = ""
        if single_room:
            extra_clause = "AND events.room_id = ?"
            tuple_args.append(last_room_id)

        sql = """
            SELECT
                event_id, state_events.type, state_events.state_key,
                topological_ordering, stream_ordering,
                events.room_id
            FROM events
            INNER JOIN state_events USING (event_id)
            LEFT JOIN event_auth_chains USING (event_id)
            LEFT JOIN event_auth_chain_to_calculate USING (event_id)
            WHERE event_auth_chains.event_id IS NULL
                AND event_auth_chain_to_calculate.event_id IS NULL
                AND %(tuple_cmp)s
                %(extra)s
            ORDER BY events.room_id, topological_ordering, stream_ordering
            %(limit)s
        """ % {
            "tuple_cmp": tuple_clause,
            "limit": "LIMIT ?" if batch_size is not None else "",
            "extra": extra_clause,
        }

        if batch_size is not None:
            tuple_args.append(batch_size)

        txn.execute(sql, tuple_args)
        rows = txn.fetchall()

        # Put the results in the necessary format for
        # `_add_chain_cover_index`
        event_to_room_id = {row[0]: row[5] for row in rows}
        event_to_types = {row[0]: (row[1], row[2]) for row in rows}

        # Calculate the new last position we've processed up to.
        new_last_depth = rows[-1][3] if rows else last_depth  # type: int
        new_last_stream = rows[-1][4] if rows else last_stream  # type: int
        new_last_room_id = rows[-1][5] if rows else ""  # type: str

        # Map from room_id to last depth/stream_ordering processed for the room,
        # excluding the last room (which we're likely still processing). We also
        # need to include the room passed in if it's not included in the result
        # set (as we then know we've processed all events in said room).
        #
        # This is the set of rooms that we can now safely flip the
        # `has_auth_chain_index` bit for.
        finished_rooms = {
            row[5]: (row[3], row[4]) for row in rows if row[5] != new_last_room_id
        }
        if last_room_id not in finished_rooms and last_room_id != new_last_room_id:
            finished_rooms[last_room_id] = (last_depth, last_stream)

        count = len(rows)

        # We also need to fetch the auth events for them.
        auth_events = self.db_pool.simple_select_many_txn(
            txn,
            table="event_auth",
            column="event_id",
            iterable=event_to_room_id,
            keyvalues={},
            retcols=("event_id", "auth_id"),
        )

        event_to_auth_chain = {}  # type: Dict[str, List[str]]
        for row in auth_events:
            event_to_auth_chain.setdefault(row["event_id"], []).append(row["auth_id"])

        # Calculate and persist the chain cover index for this set of events.
        #
        # Annoyingly we need to gut wrench into the persit event store so that
        # we can reuse the function to calculate the chain cover for rooms.
        PersistEventsStore._add_chain_cover_index(
            txn,
            self.db_pool,
            event_to_room_id,
            event_to_types,
            event_to_auth_chain,
        )

        return _CalculateChainCover(
            room_id=new_last_room_id,
            depth=new_last_depth,
            stream=new_last_stream,
            processed_count=count,
            finished_room_map=finished_rooms,
        )
