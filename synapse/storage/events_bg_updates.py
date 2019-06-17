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

from six import text_type

from canonicaljson import json

from twisted.internet import defer

from synapse.storage.background_updates import BackgroundUpdateStore

logger = logging.getLogger(__name__)


class EventsBackgroundUpdatesStore(BackgroundUpdateStore):

    EVENT_ORIGIN_SERVER_TS_NAME = "event_origin_server_ts"
    EVENT_FIELDS_SENDER_URL_UPDATE_NAME = "event_fields_sender_url"
    DELETE_SOFT_FAILED_EXTREMITIES = "delete_soft_failed_extremities"

    def __init__(self, db_conn, hs):
        super(EventsBackgroundUpdatesStore, self).__init__(db_conn, hs)

        self.register_background_update_handler(
            self.EVENT_ORIGIN_SERVER_TS_NAME, self._background_reindex_origin_server_ts
        )
        self.register_background_update_handler(
            self.EVENT_FIELDS_SENDER_URL_UPDATE_NAME,
            self._background_reindex_fields_sender,
        )

        self.register_background_index_update(
            "event_contains_url_index",
            index_name="event_contains_url_index",
            table="events",
            columns=["room_id", "topological_ordering", "stream_ordering"],
            where_clause="contains_url = true AND outlier = false",
        )

        # an event_id index on event_search is useful for the purge_history
        # api. Plus it means we get to enforce some integrity with a UNIQUE
        # clause
        self.register_background_index_update(
            "event_search_event_id_idx",
            index_name="event_search_event_id_idx",
            table="event_search",
            columns=["event_id"],
            unique=True,
            psql_only=True,
        )

        self.register_background_update_handler(
            self.DELETE_SOFT_FAILED_EXTREMITIES, self._cleanup_extremities_bg_update
        )

    @defer.inlineCallbacks
    def _background_reindex_fields_sender(self, progress, batch_size):
        target_min_stream_id = progress["target_min_stream_id_inclusive"]
        max_stream_id = progress["max_stream_id_exclusive"]
        rows_inserted = progress.get("rows_inserted", 0)

        INSERT_CLUMP_SIZE = 1000

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
                    event_json = json.loads(row[2])
                    sender = event_json["sender"]
                    content = event_json["content"]

                    contains_url = "url" in content
                    if contains_url:
                        contains_url &= isinstance(content["url"], text_type)
                except (KeyError, AttributeError):
                    # If the event is missing a necessary field then
                    # skip over it.
                    continue

                update_rows.append((sender, contains_url, event_id))

            sql = "UPDATE events SET sender = ?, contains_url = ? WHERE event_id = ?"

            for index in range(0, len(update_rows), INSERT_CLUMP_SIZE):
                clump = update_rows[index : index + INSERT_CLUMP_SIZE]
                txn.executemany(sql, clump)

            progress = {
                "target_min_stream_id_inclusive": target_min_stream_id,
                "max_stream_id_exclusive": min_stream_id,
                "rows_inserted": rows_inserted + len(rows),
            }

            self._background_update_progress_txn(
                txn, self.EVENT_FIELDS_SENDER_URL_UPDATE_NAME, progress
            )

            return len(rows)

        result = yield self.runInteraction(
            self.EVENT_FIELDS_SENDER_URL_UPDATE_NAME, reindex_txn
        )

        if not result:
            yield self._end_background_update(self.EVENT_FIELDS_SENDER_URL_UPDATE_NAME)

        defer.returnValue(result)

    @defer.inlineCallbacks
    def _background_reindex_origin_server_ts(self, progress, batch_size):
        target_min_stream_id = progress["target_min_stream_id_inclusive"]
        max_stream_id = progress["max_stream_id_exclusive"]
        rows_inserted = progress.get("rows_inserted", 0)

        INSERT_CLUMP_SIZE = 1000

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
                ev_rows = self._simple_select_many_txn(
                    txn,
                    table="event_json",
                    column="event_id",
                    iterable=chunk,
                    retcols=["event_id", "json"],
                    keyvalues={},
                )

                for row in ev_rows:
                    event_id = row["event_id"]
                    event_json = json.loads(row["json"])
                    try:
                        origin_server_ts = event_json["origin_server_ts"]
                    except (KeyError, AttributeError):
                        # If the event is missing a necessary field then
                        # skip over it.
                        continue

                    rows_to_update.append((origin_server_ts, event_id))

            sql = "UPDATE events SET origin_server_ts = ? WHERE event_id = ?"

            for index in range(0, len(rows_to_update), INSERT_CLUMP_SIZE):
                clump = rows_to_update[index : index + INSERT_CLUMP_SIZE]
                txn.executemany(sql, clump)

            progress = {
                "target_min_stream_id_inclusive": target_min_stream_id,
                "max_stream_id_exclusive": min_stream_id,
                "rows_inserted": rows_inserted + len(rows_to_update),
            }

            self._background_update_progress_txn(
                txn, self.EVENT_ORIGIN_SERVER_TS_NAME, progress
            )

            return len(rows_to_update)

        result = yield self.runInteraction(
            self.EVENT_ORIGIN_SERVER_TS_NAME, reindex_search_txn
        )

        if not result:
            yield self._end_background_update(self.EVENT_ORIGIN_SERVER_TS_NAME)

        defer.returnValue(result)

    @defer.inlineCallbacks
    def _cleanup_extremities_bg_update(self, progress, batch_size):
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
                    soft_failed = json.loads(metadata).get("soft_failed")

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
                        prev_event_id IN (%s)
                        AND NOT events.outlier
                """ % (
                    ",".join("?" for _ in to_check),
                )
                txn.execute(sql, to_check)

                for prev_event_id, event_id, metadata, rejected in txn:
                    if event_id in graph:
                        # Already handled this event previously, but we still
                        # want to record the edge.
                        graph[event_id].add(prev_event_id)
                        continue

                    graph[event_id] = {prev_event_id}

                    soft_failed = json.loads(metadata).get("soft_failed")
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

            deleted = self._simple_delete_many_txn(
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
                rows = self._simple_select_many_txn(
                    txn,
                    table="events",
                    column="event_id",
                    iterable=to_delete,
                    keyvalues={},
                    retcols=("room_id",),
                )
                room_ids = set(row["room_id"] for row in rows)
                for room_id in room_ids:
                    txn.call_after(
                        self.get_latest_event_ids_in_room.invalidate, (room_id,)
                    )

            self._simple_delete_many_txn(
                txn=txn,
                table="_extremities_to_check",
                column="event_id",
                iterable=original_set,
                keyvalues={},
            )

            return len(original_set)

        num_handled = yield self.runInteraction(
            "_cleanup_extremities_bg_update", _cleanup_extremities_bg_update_txn
        )

        if not num_handled:
            yield self._end_background_update(self.DELETE_SOFT_FAILED_EXTREMITIES)

            def _drop_table_txn(txn):
                txn.execute("DROP TABLE _extremities_to_check")

            yield self.runInteraction(
                "_cleanup_extremities_bg_update_drop_table", _drop_table_txn
            )

        defer.returnValue(num_handled)
