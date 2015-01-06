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

from ._base import SQLBaseStore, Table

from collections import namedtuple

from twisted.internet import defer

import logging

logger = logging.getLogger(__name__)


class TransactionStore(SQLBaseStore):
    """A collection of queries for handling PDUs.
    """

    # a write-through cache of DestinationsTable.EntryType indexed by
    # destination string
    destination_retry_cache = {}

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
        where_clause = "transaction_id = ? AND origin = ?"
        query = ReceivedTransactionsTable.select_statement(where_clause)

        txn.execute(query, (transaction_id, origin))

        results = ReceivedTransactionsTable.decode_results(txn.fetchall())

        if results and results[0].response_code:
            return (results[0].response_code, results[0].response_json)
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

        return self.runInteraction(
            "set_received_txn_response",
            self._set_received_txn_response,
            transaction_id, origin, code, response_dict
        )

    def _set_received_txn_response(self, txn, transaction_id, origin, code,
                                   response_json):
        query = (
            "UPDATE %s "
            "SET response_code = ?, response_json = ? "
            "WHERE transaction_id = ? AND origin = ?"
        ) % ReceivedTransactionsTable.table_name

        txn.execute(query, (code, response_json, transaction_id, origin))

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

        # First we find out what the prev_txns should be.
        # Since we know that we are only sending one transaction at a time,
        # we can simply take the last one.
        query = "%s ORDER BY id DESC LIMIT 1" % (
                SentTransactions.select_statement("destination = ?"),
            )

        results = txn.execute(query, (destination,))
        results = SentTransactions.decode_results(results)

        prev_txns = [r.transaction_id for r in results]

        # Actually add the new transaction to the sent_transactions table.

        query = SentTransactions.insert_statement()
        txn.execute(query, SentTransactions.EntryType(
            None,
            transaction_id=transaction_id,
            destination=destination,
            ts=origin_server_ts,
            response_code=0,
            response_json=None
        ))

        # Update the tx id -> pdu id mapping

        # values = [
        #     (transaction_id, destination, pdu[0], pdu[1])
        #     for pdu in pdu_list
        # ]
        #
        # logger.debug("Inserting: %s", repr(values))
        #
        # query = TransactionsToPduTable.insert_statement()
        # txn.executemany(query, values)

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
            transaction_id, destination, code, response_dict
        )

    def _delivered_txn(cls, txn, transaction_id, destination,
                       code, response_json):
        query = (
            "UPDATE %s "
            "SET response_code = ?, response_json = ? "
            "WHERE transaction_id = ? AND destination = ?"
        ) % SentTransactions.table_name

        txn.execute(query, (code, response_json, transaction_id, destination))

    def get_transactions_after(self, transaction_id, destination):
        """Get all transactions after a given local transaction_id.

        Args:
            transaction_id (str)
            destination (str)

        Returns:
            list: A list of `ReceivedTransactionsTable.EntryType`
        """
        return self.runInteraction(
            "get_transactions_after",
            self._get_transactions_after, transaction_id, destination
        )

    def _get_transactions_after(cls, txn, transaction_id, destination):
        where = (
            "destination = ? AND id > (select id FROM %s WHERE "
            "transaction_id = ? AND destination = ?)"
        ) % (
            SentTransactions.table_name
        )
        query = SentTransactions.select_statement(where)

        txn.execute(query, (destination, transaction_id, destination))

        return ReceivedTransactionsTable.decode_results(txn.fetchall())

    def get_destination_retry_timings(self, destination):
        """Gets the current retry timings (if any) for a given destination.

        Args:
            destination (str)

        Returns:
            None if not retrying
            Otherwise a DestinationsTable.EntryType for the retry scheme
        """
        if destination in self.destination_retry_cache:
            return defer.succeed(self.destination_retry_cache[destination])

        return self.runInteraction(
            "get_destination_retry_timings",
            self._get_destination_retry_timings, destination)

    def _get_destination_retry_timings(cls, txn, destination):
        query = DestinationsTable.select_statement("destination = ?")
        txn.execute(query, (destination,))
        result = txn.fetchall()
        if result:
            result = DestinationsTable.decode_single_result(result)
            if result.retry_last_ts > 0:
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

        self.destination_retry_cache[destination] = (
            DestinationsTable.EntryType(
                destination,
                retry_last_ts,
                retry_interval
            )
        )

        # XXX: we could chose to not bother persisting this if our cache thinks
        # this is a NOOP
        return self.runInteraction(
            "set_destination_retry_timings",
            self._set_destination_retry_timings,
            destination,
            retry_last_ts,
            retry_interval,
        )

    def _set_destination_retry_timings(cls, txn, destination,
                                       retry_last_ts, retry_interval):

        query = (
            "INSERT OR REPLACE INTO %s "
            "(destination, retry_last_ts, retry_interval) "
            "VALUES (?, ?, ?) "
        ) % DestinationsTable.table_name

        txn.execute(query, (destination, retry_last_ts, retry_interval))

    def get_destinations_needing_retry(self):
        """Get all destinations which are due a retry for sending a transaction.

        Returns:
            list: A list of `DestinationsTable.EntryType`
        """

        return self.runInteraction(
            "get_destinations_needing_retry",
            self._get_destinations_needing_retry
        )

    def _get_destinations_needing_retry(cls, txn):
        where = "retry_last_ts > 0 and retry_next_ts < now()"
        query = DestinationsTable.select_statement(where)
        txn.execute(query)
        return DestinationsTable.decode_results(txn.fetchall())


class ReceivedTransactionsTable(Table):
    table_name = "received_transactions"

    fields = [
        "transaction_id",
        "origin",
        "ts",
        "response_code",
        "response_json",
        "has_been_referenced",
    ]

    EntryType = namedtuple("ReceivedTransactionsEntry", fields)


class SentTransactions(Table):
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


class TransactionsToPduTable(Table):
    table_name = "transaction_id_to_pdu"

    fields = [
        "transaction_id",
        "destination",
        "pdu_id",
        "pdu_origin",
    ]

    EntryType = namedtuple("TransactionsToPduEntry", fields)


class DestinationsTable(Table):
    table_name = "destinations"

    fields = [
        "destination",
        "retry_last_ts",
        "retry_interval",
    ]

    EntryType = namedtuple("DestinationsEntry", fields)
