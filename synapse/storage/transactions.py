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

from ._base import SQLBaseStore
from synapse.util.caches.descriptors import cached

from collections import namedtuple

from canonicaljson import encode_canonical_json
import logging

logger = logging.getLogger(__name__)


class TransactionStore(SQLBaseStore):
    """A collection of queries for handling PDUs.
    """

    def get_received_txn_response(self, transaction_id, origin):
        """For an incoming transaction from a given origin, check if we have
        already responded to it. If so, return the response code and response
        body (as a dict).

        Args:
            transaction_id (str)
            origin(str)

        Returns:
            tuple: None if we have not previously responded to
            this transaction or a 2-tuple of (int, dict)
        """

        return self.runInteraction(
            "get_received_txn_response",
            self._get_received_txn_response, transaction_id, origin
        )

    def _get_received_txn_response(self, txn, transaction_id, origin):
        result = self._simple_select_one_txn(
            txn,
            table=ReceivedTransactionsTable.table_name,
            keyvalues={
                "transaction_id": transaction_id,
                "origin": origin,
            },
            retcols=ReceivedTransactionsTable.fields,
            allow_none=True,
        )

        if result and result["response_code"]:
            return result["response_code"], result["response_json"]
        else:
            return None

    def set_received_txn_response(self, transaction_id, origin, code,
                                  response_dict):
        """Persist the response we returened for an incoming transaction, and
        should return for subsequent transactions with the same transaction_id
        and origin.

        Args:
            txn
            transaction_id (str)
            origin (str)
            code (int)
            response_json (str)
        """

        return self._simple_insert(
            table=ReceivedTransactionsTable.table_name,
            values={
                "transaction_id": transaction_id,
                "origin": origin,
                "response_code": code,
                "response_json": buffer(encode_canonical_json(response_dict)),
            },
            or_ignore=True,
            desc="set_received_txn_response",
        )

    def prep_send_transaction(self, transaction_id, destination,
                              origin_server_ts):
        """Persists an outgoing transaction and calculates the values for the
        previous transaction id list.

        This should be called before sending the transaction so that it has the
        correct value for the `prev_ids` key.

        Args:
            transaction_id (str)
            destination (str)
            origin_server_ts (int)

        Returns:
            list: A list of previous transaction ids.
        """

        return self.runInteraction(
            "prep_send_transaction",
            self._prep_send_transaction,
            transaction_id, destination, origin_server_ts
        )

    def _prep_send_transaction(self, txn, transaction_id, destination,
                               origin_server_ts):

        next_id = self._transaction_id_gen.get_next_txn(txn)

        # First we find out what the prev_txns should be.
        # Since we know that we are only sending one transaction at a time,
        # we can simply take the last one.
        query = (
            "SELECT * FROM sent_transactions"
            " WHERE destination = ?"
            " ORDER BY id DESC LIMIT 1"
        )

        txn.execute(query, (destination,))
        results = self.cursor_to_dict(txn)

        prev_txns = [r["transaction_id"] for r in results]

        # Actually add the new transaction to the sent_transactions table.

        self._simple_insert_txn(
            txn,
            table=SentTransactions.table_name,
            values={
                "id": next_id,
                "transaction_id": transaction_id,
                "destination": destination,
                "ts": origin_server_ts,
                "response_code": 0,
                "response_json": None,
            }
        )

        # TODO Update the tx id -> pdu id mapping

        return prev_txns

    def delivered_txn(self, transaction_id, destination, code, response_dict):
        """Persists the response for an outgoing transaction.

        Args:
            transaction_id (str)
            destination (str)
            code (int)
            response_json (str)
        """
        return self.runInteraction(
            "delivered_txn",
            self._delivered_txn,
            transaction_id, destination, code,
            buffer(encode_canonical_json(response_dict)),
        )

    def _delivered_txn(self, txn, transaction_id, destination,
                       code, response_json):
        self._simple_update_one_txn(
            txn,
            table=SentTransactions.table_name,
            keyvalues={
                "transaction_id": transaction_id,
                "destination": destination,
            },
            updatevalues={
                "response_code": code,
                "response_json": None,  # For now, don't persist response_json
            }
        )

    def get_transactions_after(self, transaction_id, destination):
        """Get all transactions after a given local transaction_id.

        Args:
            transaction_id (str)
            destination (str)

        Returns:
            list: A list of dicts
        """
        return self.runInteraction(
            "get_transactions_after",
            self._get_transactions_after, transaction_id, destination
        )

    def _get_transactions_after(self, txn, transaction_id, destination):
        query = (
            "SELECT * FROM sent_transactions"
            " WHERE destination = ? AND id >"
            " ("
            " SELECT id FROM sent_transactions"
            " WHERE transaction_id = ? AND destination = ?"
            " )"
        )

        txn.execute(query, (destination, transaction_id, destination))

        return self.cursor_to_dict(txn)

    @cached()
    def get_destination_retry_timings(self, destination):
        """Gets the current retry timings (if any) for a given destination.

        Args:
            destination (str)

        Returns:
            None if not retrying
            Otherwise a dict for the retry scheme
        """
        return self.runInteraction(
            "get_destination_retry_timings",
            self._get_destination_retry_timings, destination)

    def _get_destination_retry_timings(self, txn, destination):
        result = self._simple_select_one_txn(
            txn,
            table=DestinationsTable.table_name,
            keyvalues={
                "destination": destination,
            },
            retcols=DestinationsTable.fields,
            allow_none=True,
        )

        if result and result["retry_last_ts"] > 0:
            return result
        else:
            return None

    def set_destination_retry_timings(self, destination,
                                      retry_last_ts, retry_interval):
        """Sets the current retry timings for a given destination.
        Both timings should be zero if retrying is no longer occuring.

        Args:
            destination (str)
            retry_last_ts (int) - time of last retry attempt in unix epoch ms
            retry_interval (int) - how long until next retry in ms
        """

        # XXX: we could chose to not bother persisting this if our cache thinks
        # this is a NOOP
        return self.runInteraction(
            "set_destination_retry_timings",
            self._set_destination_retry_timings,
            destination,
            retry_last_ts,
            retry_interval,
        )

    def _set_destination_retry_timings(self, txn, destination,
                                       retry_last_ts, retry_interval):
        txn.call_after(self.get_destination_retry_timings.invalidate, (destination,))

        self._simple_upsert_txn(
            txn,
            "destinations",
            keyvalues={
                "destination": destination,
            },
            values={
                "retry_last_ts": retry_last_ts,
                "retry_interval": retry_interval,
            },
            insertion_values={
                "destination": destination,
                "retry_last_ts": retry_last_ts,
                "retry_interval": retry_interval,
            }
        )

    def get_destinations_needing_retry(self):
        """Get all destinations which are due a retry for sending a transaction.

        Returns:
            list: A list of dicts
        """

        return self.runInteraction(
            "get_destinations_needing_retry",
            self._get_destinations_needing_retry
        )

    def _get_destinations_needing_retry(self, txn):
        query = (
            "SELECT * FROM destinations"
            " WHERE retry_last_ts > 0 and retry_next_ts < ?"
        )

        txn.execute(query, (self._clock.time_msec(),))
        return self.cursor_to_dict(txn)


class ReceivedTransactionsTable(object):
    table_name = "received_transactions"

    fields = [
        "transaction_id",
        "origin",
        "ts",
        "response_code",
        "response_json",
        "has_been_referenced",
    ]


class SentTransactions(object):
    table_name = "sent_transactions"

    fields = [
        "id",
        "transaction_id",
        "destination",
        "ts",
        "response_code",
        "response_json",
    ]

    EntryType = namedtuple("SentTransactionsEntry", fields)


class TransactionsToPduTable(object):
    table_name = "transaction_id_to_pdu"

    fields = [
        "transaction_id",
        "destination",
        "pdu_id",
        "pdu_origin",
    ]


class DestinationsTable(object):
    table_name = "destinations"

    fields = [
        "destination",
        "retry_last_ts",
        "retry_interval",
    ]
