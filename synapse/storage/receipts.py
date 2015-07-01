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

from ._base import SQLBaseStore, cached

from twisted.internet import defer


class ReceiptStore(SQLBaseStore):

    @cached
    @defer.inlineCallbacks
    def get_linearized_receipts_for_room(self, room_id):
        rows = yield self._simple_select_list(
            table="receipts_linearized",
            keyvalues={"room_id": room_id},
            retcols=["receipt_type", "user_id", "event_id"],
            desc="get_linearized_receipts_for_room",
        )

        result = {}
        for row in rows:
            result.setdefault(
                row["event_id"], {}
            ).setdefault(
                row["receipt_type"], []
            ).append(row["user_id"])

        defer.returnValue(result)

    @cached
    @defer.inlineCallbacks
    def get_graph_receipts_for_room(self, room_id):
        rows = yield self._simple_select_list(
            table="receipts_graph",
            keyvalues={"room_id": room_id},
            retcols=["receipt_type", "user_id", "event_id"],
            desc="get_linearized_receipts_for_room",
        )

        result = {}
        for row in rows:
            result.setdefault(
                row["user_id"], {}
            ).setdefault(
                row["receipt_type"], []
            ).append(row["event_id"])

        defer.returnValue(result)

    def insert_linearized_receipt_txn(self, txn, room_id, receipt_type,
                                      user_id, event_id, stream_id):
        self._simple_delete_txn(
            txn,
            table="receipts_linearized",
            keyvalues={
                "stream_id": stream_id,
                "room_id": room_id,
                "receipt_type": receipt_type,
                "user_id": user_id,
            }
        )

        self._simple_insert_txn(
            txn,
            table="receipts_linearized",
            values={
                "room_id": room_id,
                "receipt_type": receipt_type,
                "user_id": user_id,
                "event_id": event_id,
            }
        )

    @defer.inlineCallbacks
    def insert_receipt(self, room_id, receipt_type, user_id, event_ids):
        if not event_ids:
            return

        if len(event_ids) == 1:
            linearized_event_id = event_ids[0]
        else:
            # we need to points in graph -> linearized form.
            def graph_to_linear(txn):
                query = (
                    "SELECT event_id WHERE room_id = ? AND stream_ordering IN ("
                    " SELECT max(stream_ordering) WHERE event_id IN (%s)"
                    ")"
                ) % (",".join(["?"] * len(event_ids)))

                txn.execute(query, [room_id] + event_ids)
                rows = txn.fetchall()
                if rows:
                    return rows[0][0]
                else:
                    # TODO: ARGH?!
                    return None

            linearized_event_id = yield self.runInteraction(
                graph_to_linear, desc="insert_receipt_conv"
            )

        stream_id_manager = yield self._stream_id_gen.get_next(self)
        with stream_id_manager() as stream_id:
            yield self.runInteraction(
                self.insert_linearized_receipt_txn,
                room_id, receipt_type, user_id, linearized_event_id,
                stream_id=stream_id,
                desc="insert_linearized_receipt"
            )

        yield self.insert_graph_receipt(
            room_id, receipt_type, user_id, event_ids
        )

        max_persisted_id = yield self._stream_id_gen.get_max_token(self)
        defer.returnValue((stream_id, max_persisted_id))

    def insert_graph_receipt(self, room_id, receipt_type,
                             user_id, event_ids):
        return self.runInteraction(
            self.insert_graph_receipt_txn,
            room_id, receipt_type, user_id, event_ids,
            desc="insert_graph_receipt"
        )

    def insert_graph_receipt_txn(self, txn, room_id, receipt_type,
                                 user_id, event_ids):
        self._simple_delete_txn(
            txn,
            table="receipts_graph",
            keyvalues={
                "room_id": room_id,
                "receipt_type": receipt_type,
                "user_id": user_id,
            }
        )
        self._simple_insert_many_txn(
            txn,
            table="receipts_graph",
            values=[
                {
                    "room_id": room_id,
                    "receipt_type": receipt_type,
                    "user_id": user_id,
                    "event_id": event_id,
                }
                for event_id in event_ids
            ],
        )
