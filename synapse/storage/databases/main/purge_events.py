# -*- coding: utf-8 -*-
# Copyright 2020 The Matrix.org Foundation C.I.C.
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
from typing import Any, List, Set, Tuple

from synapse.api.errors import SynapseError
from synapse.storage._base import SQLBaseStore
from synapse.storage.databases.main.state import StateGroupWorkerStore
from synapse.types import RoomStreamToken

logger = logging.getLogger(__name__)


class PurgeEventsStore(StateGroupWorkerStore, SQLBaseStore):
    async def purge_history(
        self, room_id: str, token: str, delete_local_events: bool
    ) -> Set[int]:
        """Deletes room history before a certain point

        Args:
            room_id:
            token: A topological token to delete events before
            delete_local_events:
                if True, we will delete local events as well as remote ones
                (instead of just marking them as outliers and deleting their
                state groups).

        Returns:
            The set of state groups that are referenced by deleted events.
        """

        parsed_token = await RoomStreamToken.parse(self, token)

        return await self.db_pool.runInteraction(
            "purge_history",
            self._purge_history_txn,
            room_id,
            parsed_token,
            delete_local_events,
        )

    def _purge_history_txn(self, txn, room_id, token, delete_local_events):
        # Tables that should be pruned:
        #     event_auth
        #     event_backward_extremities
        #     event_edges
        #     event_forward_extremities
        #     event_json
        #     event_push_actions
        #     event_reference_hashes
        #     event_relations
        #     event_search
        #     event_to_state_groups
        #     events
        #     rejections
        #     room_depth
        #     state_groups
        #     state_groups_state
        #     destination_rooms

        # we will build a temporary table listing the events so that we don't
        # have to keep shovelling the list back and forth across the
        # connection. Annoyingly the python sqlite driver commits the
        # transaction on CREATE, so let's do this first.
        #
        # furthermore, we might already have the table from a previous (failed)
        # purge attempt, so let's drop the table first.

        txn.execute("DROP TABLE IF EXISTS events_to_purge")

        txn.execute(
            "CREATE TEMPORARY TABLE events_to_purge ("
            "    event_id TEXT NOT NULL,"
            "    should_delete BOOLEAN NOT NULL"
            ")"
        )

        # First ensure that we're not about to delete all the forward extremeties
        txn.execute(
            "SELECT e.event_id, e.depth FROM events as e "
            "INNER JOIN event_forward_extremities as f "
            "ON e.event_id = f.event_id "
            "AND e.room_id = f.room_id "
            "WHERE f.room_id = ?",
            (room_id,),
        )
        rows = txn.fetchall()
        max_depth = max(row[1] for row in rows)

        if max_depth < token.topological:
            # We need to ensure we don't delete all the events from the database
            # otherwise we wouldn't be able to send any events (due to not
            # having any backwards extremeties)
            raise SynapseError(
                400, "topological_ordering is greater than forward extremeties"
            )

        logger.info("[purge] looking for events to delete")

        should_delete_expr = "state_key IS NULL"
        should_delete_params = ()  # type: Tuple[Any, ...]
        if not delete_local_events:
            should_delete_expr += " AND event_id NOT LIKE ?"

            # We include the parameter twice since we use the expression twice
            should_delete_params += ("%:" + self.hs.hostname, "%:" + self.hs.hostname)

        should_delete_params += (room_id, token.topological)

        # Note that we insert events that are outliers and aren't going to be
        # deleted, as nothing will happen to them.
        txn.execute(
            "INSERT INTO events_to_purge"
            " SELECT event_id, %s"
            " FROM events AS e LEFT JOIN state_events USING (event_id)"
            " WHERE (NOT outlier OR (%s)) AND e.room_id = ? AND topological_ordering < ?"
            % (should_delete_expr, should_delete_expr),
            should_delete_params,
        )

        # We create the indices *after* insertion as that's a lot faster.

        # create an index on should_delete because later we'll be looking for
        # the should_delete / shouldn't_delete subsets
        txn.execute(
            "CREATE INDEX events_to_purge_should_delete"
            " ON events_to_purge(should_delete)"
        )

        # We do joins against events_to_purge for e.g. calculating state
        # groups to purge, etc., so lets make an index.
        txn.execute("CREATE INDEX events_to_purge_id ON events_to_purge(event_id)")

        txn.execute("SELECT event_id, should_delete FROM events_to_purge")
        event_rows = txn.fetchall()
        logger.info(
            "[purge] found %i events before cutoff, of which %i can be deleted",
            len(event_rows),
            sum(1 for e in event_rows if e[1]),
        )

        logger.info("[purge] Finding new backward extremities")

        # We calculate the new entries for the backward extremeties by finding
        # events to be purged that are pointed to by events we're not going to
        # purge.
        txn.execute(
            "SELECT DISTINCT e.event_id FROM events_to_purge AS e"
            " INNER JOIN event_edges AS ed ON e.event_id = ed.prev_event_id"
            " LEFT JOIN events_to_purge AS ep2 ON ed.event_id = ep2.event_id"
            " WHERE ep2.event_id IS NULL"
        )
        new_backwards_extrems = txn.fetchall()

        logger.info("[purge] replacing backward extremities: %r", new_backwards_extrems)

        txn.execute(
            "DELETE FROM event_backward_extremities WHERE room_id = ?", (room_id,)
        )

        # Update backward extremeties
        txn.execute_batch(
            "INSERT INTO event_backward_extremities (room_id, event_id)"
            " VALUES (?, ?)",
            [(room_id, event_id) for event_id, in new_backwards_extrems],
        )

        logger.info("[purge] finding state groups referenced by deleted events")

        # Get all state groups that are referenced by events that are to be
        # deleted.
        txn.execute(
            """
            SELECT DISTINCT state_group FROM events_to_purge
            INNER JOIN event_to_state_groups USING (event_id)
        """
        )

        referenced_state_groups = {sg for sg, in txn}
        logger.info(
            "[purge] found %i referenced state groups", len(referenced_state_groups)
        )

        logger.info("[purge] removing events from event_to_state_groups")
        txn.execute(
            "DELETE FROM event_to_state_groups "
            "WHERE event_id IN (SELECT event_id from events_to_purge)"
        )
        for event_id, _ in event_rows:
            txn.call_after(self._get_state_group_for_event.invalidate, (event_id,))

        # Delete all remote non-state events
        for table in (
            "events",
            "event_json",
            "event_auth",
            "event_edges",
            "event_forward_extremities",
            "event_reference_hashes",
            "event_relations",
            "event_search",
            "rejections",
        ):
            logger.info("[purge] removing events from %s", table)

            txn.execute(
                "DELETE FROM %s WHERE event_id IN ("
                "    SELECT event_id FROM events_to_purge WHERE should_delete"
                ")" % (table,)
            )

        # event_push_actions lacks an index on event_id, and has one on
        # (room_id, event_id) instead.
        for table in ("event_push_actions",):
            logger.info("[purge] removing events from %s", table)

            txn.execute(
                "DELETE FROM %s WHERE room_id = ? AND event_id IN ("
                "    SELECT event_id FROM events_to_purge WHERE should_delete"
                ")" % (table,),
                (room_id,),
            )

        # Mark all state and own events as outliers
        logger.info("[purge] marking remaining events as outliers")
        txn.execute(
            "UPDATE events SET outlier = ?"
            " WHERE event_id IN ("
            "    SELECT event_id FROM events_to_purge "
            "    WHERE NOT should_delete"
            ")",
            (True,),
        )

        # synapse tries to take out an exclusive lock on room_depth whenever it
        # persists events (because upsert), and once we run this update, we
        # will block that for the rest of our transaction.
        #
        # So, let's stick it at the end so that we don't block event
        # persistence.
        #
        # We do this by calculating the minimum depth of the backwards
        # extremities. However, the events in event_backward_extremities
        # are ones we don't have yet so we need to look at the events that
        # point to it via event_edges table.
        txn.execute(
            """
            SELECT COALESCE(MIN(depth), 0)
            FROM event_backward_extremities AS eb
            INNER JOIN event_edges AS eg ON eg.prev_event_id = eb.event_id
            INNER JOIN events AS e ON e.event_id = eg.event_id
            WHERE eb.room_id = ?
        """,
            (room_id,),
        )
        (min_depth,) = txn.fetchone()

        logger.info("[purge] updating room_depth to %d", min_depth)

        txn.execute(
            "UPDATE room_depth SET min_depth = ? WHERE room_id = ?",
            (min_depth, room_id),
        )

        # finally, drop the temp table. this will commit the txn in sqlite,
        # so make sure to keep this actually last.
        txn.execute("DROP TABLE events_to_purge")

        logger.info("[purge] done")

        return referenced_state_groups

    async def purge_room(self, room_id: str) -> List[int]:
        """Deletes all record of a room

        Args:
            room_id

        Returns:
            The list of state groups to delete.
        """
        return await self.db_pool.runInteraction(
            "purge_room", self._purge_room_txn, room_id
        )

    def _purge_room_txn(self, txn, room_id):
        # First we fetch all the state groups that should be deleted, before
        # we delete that information.
        txn.execute(
            """
                SELECT DISTINCT state_group FROM events
                INNER JOIN event_to_state_groups USING(event_id)
                WHERE events.room_id = ?
            """,
            (room_id,),
        )

        state_groups = [row[0] for row in txn]

        # Now we delete tables which lack an index on room_id but have one on event_id
        for table in (
            "event_auth",
            "event_edges",
            "event_json",
            "event_push_actions_staging",
            "event_reference_hashes",
            "event_relations",
            "event_to_state_groups",
            "redactions",
            "rejections",
            "state_events",
        ):
            logger.info("[purge] removing %s from %s", room_id, table)

            txn.execute(
                """
                DELETE FROM %s WHERE event_id IN (
                  SELECT event_id FROM events WHERE room_id=?
                )
                """
                % (table,),
                (room_id,),
            )

        # and finally, the tables with an index on room_id (or no useful index)
        for table in (
            "current_state_events",
            "destination_rooms",
            "event_backward_extremities",
            "event_forward_extremities",
            "event_push_actions",
            "event_search",
            "events",
            "group_rooms",
            "public_room_list_stream",
            "receipts_graph",
            "receipts_linearized",
            "room_aliases",
            "room_depth",
            "room_memberships",
            "room_stats_state",
            "room_stats_current",
            "room_stats_historical",
            "room_stats_earliest_token",
            "rooms",
            "stream_ordering_to_exterm",
            "users_in_public_rooms",
            "users_who_share_private_rooms",
            # no useful index, but let's clear them anyway
            "appservice_room_list",
            "e2e_room_keys",
            "event_push_summary",
            "pusher_throttle",
            "group_summary_rooms",
            "room_account_data",
            "room_tags",
            "local_current_membership",
        ):
            logger.info("[purge] removing %s from %s", room_id, table)
            txn.execute("DELETE FROM %s WHERE room_id=?" % (table,), (room_id,))

        # Other tables we do NOT need to clear out:
        #
        #  - blocked_rooms
        #    This is important, to make sure that we don't accidentally rejoin a blocked
        #    room after it was purged
        #
        #  - user_directory
        #    This has a room_id column, but it is unused
        #

        # Other tables that we might want to consider clearing out include:
        #
        #  - event_reports
        #       Given that these are intended for abuse management my initial
        #       inclination is to leave them in place.
        #
        #  - current_state_delta_stream
        #  - ex_outlier_stream
        #  - room_tags_revisions
        #       The problem with these is that they are largeish and there is no room_id
        #       index on them. In any case we should be clearing out 'stream' tables
        #       periodically anyway (#5888)

        # TODO: we could probably usefully do a bunch of cache invalidation here

        logger.info("[purge] done")

        return state_groups
