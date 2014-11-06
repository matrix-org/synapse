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

from ._base import SQLBaseStore
from syutil.base64util import encode_base64

import logging


logger = logging.getLogger(__name__)


class EventFederationStore(SQLBaseStore):

    def get_oldest_events_in_room(self, room_id):
        return self.runInteraction(
            "get_oldest_events_in_room",
            self._get_oldest_events_in_room_txn,
            room_id,
        )

    def _get_oldest_events_in_room_txn(self, txn, room_id):
        return self._simple_select_onecol_txn(
            txn,
            table="event_backward_extremities",
            keyvalues={
                "room_id": room_id,
            },
            retcol="event_id",
        )

    def get_latest_events_in_room(self, room_id):
        return self.runInteraction(
            "get_latest_events_in_room",
            self._get_latest_events_in_room,
            room_id,
        )

    def _get_latest_events_in_room(self, txn, room_id):
        sql = (
            "SELECT e.event_id, e.depth FROM events as e "
            "INNER JOIN event_forward_extremities as f "
            "ON e.event_id = f.event_id "
            "WHERE f.room_id = ?"
        )

        txn.execute(sql, (room_id, ))

        results = []
        for event_id, depth in txn.fetchall():
            hashes = self._get_event_reference_hashes_txn(txn, event_id)
            prev_hashes = {
                k: encode_base64(v) for k, v in hashes.items()
                if k == "sha256"
            }
            results.append((event_id, prev_hashes, depth))

        return results

    def _get_latest_state_in_room(self, txn, room_id, type, state_key):
        event_ids = self._simple_select_onecol_txn(
            txn,
            table="state_forward_extremities",
            keyvalues={
                "room_id": room_id,
                "type": type,
                "state_key": state_key,
            },
            retcol="event_id",
        )

        results = []
        for event_id in event_ids:
            hashes = self._get_event_reference_hashes_txn(txn, event_id)
            prev_hashes = {
                k: encode_base64(v) for k, v in hashes.items()
                if k == "sha256"
            }
            results.append((event_id, prev_hashes))

        return results

    def _get_prev_events(self, txn, event_id):
        results = self._get_prev_events_and_state(
            txn,
            event_id,
            is_state=0,
        )

        return [(e_id, h, ) for e_id, h, _ in results]

    def _get_prev_state(self, txn, event_id):
        results = self._get_prev_events_and_state(
            txn,
            event_id,
            is_state=1,
        )

        return [(e_id, h, ) for e_id, h, _ in results]

    def _get_prev_events_and_state(self, txn, event_id, is_state=None):
        keyvalues = {
            "event_id": event_id,
        }

        if is_state is not None:
            keyvalues["is_state"] = is_state

        res = self._simple_select_list_txn(
            txn,
            table="event_edges",
            keyvalues=keyvalues,
            retcols=["prev_event_id", "is_state"],
        )

        results = []
        for d in res:
            hashes = self._get_event_reference_hashes_txn(
                txn,
                d["prev_event_id"]
            )
            prev_hashes = {
                k: encode_base64(v) for k, v in hashes.items()
                if k == "sha256"
            }
            results.append((d["prev_event_id"], prev_hashes, d["is_state"]))

        return results

    def _get_auth_events(self, txn, event_id):
        auth_ids = self._simple_select_onecol_txn(
            txn,
            table="event_auth",
            keyvalues={
                "event_id": event_id,
            },
            retcol="auth_id",
        )

        results = []
        for auth_id in auth_ids:
            hashes = self._get_event_reference_hashes_txn(txn, auth_id)
            prev_hashes = {
                k: encode_base64(v) for k, v in hashes.items()
                if k == "sha256"
            }
            results.append((auth_id, prev_hashes))

        return results

    def get_min_depth(self, room_id):
        return self.runInteraction(
            "get_min_depth",
            self._get_min_depth_interaction,
            room_id,
        )

    def _get_min_depth_interaction(self, txn, room_id):
        min_depth = self._simple_select_one_onecol_txn(
            txn,
            table="room_depth",
            keyvalues={"room_id": room_id,},
            retcol="min_depth",
            allow_none=True,
        )

        return int(min_depth) if min_depth is not None else None

    def _update_min_depth_for_room_txn(self, txn, room_id, depth):
        min_depth = self._get_min_depth_interaction(txn, room_id)

        do_insert = depth < min_depth if min_depth else True

        if do_insert:
            self._simple_insert_txn(
                txn,
                table="room_depth",
                values={
                    "room_id": room_id,
                    "min_depth": depth,
                },
                or_replace=True,
            )

    def _handle_prev_events(self, txn, outlier, event_id, prev_events,
                            room_id):
        for e_id, _ in prev_events:
            # TODO (erikj): This could be done as a bulk insert
            self._simple_insert_txn(
                txn,
                table="event_edges",
                values={
                    "event_id": event_id,
                    "prev_event_id": e_id,
                    "room_id": room_id,
                    "is_state": 0,
                },
                or_ignore=True,
            )

        # Update the extremities table if this is not an outlier.
        if not outlier:
            for e_id, _ in prev_events:
                # TODO (erikj): This could be done as a bulk insert
                self._simple_delete_txn(
                    txn,
                    table="event_forward_extremities",
                    keyvalues={
                        "event_id": e_id,
                        "room_id": room_id,
                    }
                )



            # We only insert as a forward extremity the new pdu if there are no
            # other pdus that reference it as a prev pdu
            query = (
                "INSERT OR IGNORE INTO %(table)s (event_id, room_id) "
                "SELECT ?, ? WHERE NOT EXISTS ("
                "SELECT 1 FROM %(event_edges)s WHERE "
                "prev_event_id = ? "
                ")"
            ) % {
                "table": "event_forward_extremities",
                "event_edges": "event_edges",
            }

            logger.debug("query: %s", query)

            txn.execute(query, (event_id, room_id, event_id))

            # Insert all the prev_pdus as a backwards thing, they'll get
            # deleted in a second if they're incorrect anyway.
            for e_id, _ in prev_events:
                # TODO (erikj): This could be done as a bulk insert
                self._simple_insert_txn(
                    txn,
                    table="event_backward_extremities",
                    values={
                        "event_id": e_id,
                        "room_id": room_id,
                    },
                    or_ignore=True,
                )

            # Also delete from the backwards extremities table all ones that
            # reference pdus that we have already seen
            query = (
                "DELETE FROM event_backward_extremities WHERE EXISTS ("
                "SELECT 1 FROM events "
                "WHERE "
                "event_backward_extremities.event_id = events.event_id "
                "AND not events.outlier "
                ")"
            )
            txn.execute(query)


    def get_backfill_events(self, room_id, event_list, limit):
        """Get a list of Events for a given topic that occured before (and
        including) the pdus in pdu_list. Return a list of max size `limit`.

        Args:
            txn
            room_id (str)
            event_list (list)
            limit (int)

        Return:
            list: A list of PduTuples
        """
        return self.runInteraction(
            "get_backfill_events",
            self._get_backfill_events, room_id, event_list, limit
        )

    def _get_backfill_events(self, txn, room_id, event_list, limit):
        logger.debug(
            "_get_backfill_events: %s, %s, %s",
            room_id, repr(event_list), limit
        )

        # We seed the pdu_results with the things from the pdu_list.
        event_results = event_list

        front = event_list

        query = (
            "SELECT prev_event_id FROM event_edges "
            "WHERE room_id = ? AND event_id = ? "
            "LIMIT ?"
        )

        # We iterate through all event_ids in `front` to select their previous
        # events. These are dumped in `new_front`.
        # We continue until we reach the limit *or* new_front is empty (i.e.,
        # we've run out of things to select
        while front and len(event_results) < limit:

            new_front = []
            for event_id in front:
                logger.debug(
                    "_backfill_interaction: id=%s",
                    event_id
                )

                txn.execute(
                    query,
                    (room_id, event_id, limit - len(event_results))
                )

                for row in txn.fetchall():
                    logger.debug(
                        "_backfill_interaction: got id=%s",
                        *row
                    )
                    new_front.append(row)

            front = new_front
            event_results += new_front

        # We also want to update the `prev_pdus` attributes before returning.
        return self._get_pdu_tuples(txn, event_results)
