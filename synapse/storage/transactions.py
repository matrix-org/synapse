# -*- coding: utf-8 -*-
# Copyright 2014 matrix.org
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
from .pdu import PdusTable

from collections import namedtuple

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

        return self._db_pool.runInteraction(
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

        return self._db_pool.runInteraction(
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

    def prep_send_transaction(self, transaction_id, destination, ts, pdu_list):
        """Persists an outgoing transaction and calculates the values for the
        previous transaction id list.

        This should be called before sending the transaction so that it has the
        correct value for the `prev_ids` key.

        Args:
            transaction_id (str)
            destination (str)
            ts (int)
            pdu_list (list)

        Returns:
            list: A list of previous transaction ids.
        """

        return self._db_pool.runInteraction(
            self._prep_send_transaction,
            transaction_id, destination, ts, pdu_list
        )

    def _prep_send_transaction(self, txn, transaction_id, destination, ts,
                               pdu_list):

        # First we find out what the prev_txs should be.
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
            ts=ts,
            response_code=0,
            response_json=None
        ))

        # Update the tx id -> pdu id mapping

        values = [
            (transaction_id, destination, pdu[0], pdu[1])
            for pdu in pdu_list
        ]

        logger.debug("Inserting: %s", repr(values))

        query = TransactionsToPduTable.insert_statement()
        txn.executemany(query, values)

        return prev_txns

    def delivered_txn(self, transaction_id, destination, code, response_dict):
        """Persists the response for an outgoing transaction.

        Args:
            transaction_id (str)
            destination (str)
            code (int)
            response_json (str)
        """
        return self._db_pool.runInteraction(
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
        return self._db_pool.runInteraction(
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

    def get_pdus_after_transaction(self, transaction_id, destination):
        """For a given local transaction_id that we sent to a given destination
        home server, return a list of PDUs that were sent to that destination
        after it.

        Args:
            txn
            transaction_id (str)
            destination (str)

        Returns
            list: A list of PduTuple
        """
        return self._db_pool.runInteraction(
            self._get_pdus_after_transaction,
            transaction_id, destination
        )

    def _get_pdus_after_transaction(self, txn, transaction_id, destination):

        # Query that first get's all transaction_ids with an id greater than
        # the one given from the `sent_transactions` table. Then JOIN on this
        # from the `tx->pdu` table to get a list of (pdu_id, origin) that
        # specify the pdus that were sent in those transactions.
        query = (
            "SELECT pdu_id, pdu_origin FROM %(tx_pdu)s as tp "
            "INNER JOIN %(sent_tx)s as st "
            "ON tp.transaction_id = st.transaction_id "
            "AND tp.destination = st.destination "
            "WHERE st.id > ("
            "SELECT id FROM %(sent_tx)s "
            "WHERE transaction_id = ? AND destination = ?"
        ) % {
            "tx_pdu": TransactionsToPduTable.table_name,
            "sent_tx": SentTransactions.table_name,
        }

        txn.execute(query, (transaction_id, destination))

        pdus = PdusTable.decode_results(txn.fetchall())

        return self._get_pdu_tuples(txn, pdus)


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
