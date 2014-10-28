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
from twisted.internet import defer

import logging


logger = logging.getLogger(__name__)


class EventFederationStore(SQLBaseStore):

    def _get_latest_events_in_room(self, txn, room_id):
        self._simple_select_onecol_txn(
            txn,
            table="event_forward_extremities",
            keyvalues={
                "room_id": room_id,
            },
            retcol="event_id",
        )

        results = []
        for pdu_id, origin, depth in txn.fetchall():
            hashes = self._get_pdu_reference_hashes_txn(txn, pdu_id, origin)
            sha256_bytes = hashes["sha256"]
            prev_hashes = {"sha256": encode_base64(sha256_bytes)}
            results.append((pdu_id, origin, prev_hashes, depth))

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
        for e_id in prev_events:
            # TODO (erikj): This could be done as a bulk insert
            self._simple_insert_txn(
                txn,
                table="event_edges",
                values={
                    "event_id": event_id,
                    "prev_event": e_id,
                    "room_id": room_id,
                }
            )

        # Update the extremities table if this is not an outlier.
        if not outlier:
            for e_id in prev_events:
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
                "INSERT INTO %(table)s (event_id, room_id) "
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
            for e_id in prev_events:
                # TODO (erikj): This could be done as a bulk insert
                self._simple_insert_txn(
                    txn,
                    table="event_backward_extremities",
                    values={
                        "event_id": e_id,
                        "room_id": room_id,
                    }
                )

            # Also delete from the backwards extremities table all ones that
            # reference pdus that we have already seen
            query = (
                "DELETE FROM %(event_back)s as b WHERE EXISTS ("
                "SELECT 1 FROM %(events)s AS events "
                "WHERE "
                "b.event_id = events.event_id "
                "AND not events.outlier "
                ")"
            ) % {
                "event_back": "event_backward_extremities",
                "events": "events",
            }
            txn.execute(query)