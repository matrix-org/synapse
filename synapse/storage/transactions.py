# -*- coding: utf-8 -*-
# Copyright 2014-2016 OpenMarket Ltd
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

from twisted.internet import defer, reactor

from canonicaljson import encode_canonical_json

from collections import namedtuple

import itertools
import logging
import ujson as json

logger = logging.getLogger(__name__)


_TransactionRow = namedtuple(
    "_TransactionRow", (
        "id", "transaction_id", "destination", "ts", "response_code",
        "response_json",
    )
)

_UpdateTransactionRow = namedtuple(
    "_TransactionRow", (
        "response_code", "response_json",
    )
)


class TransactionStore(SQLBaseStore):
    """A collection of queries for handling PDUs.
    """

    def __init__(self, hs):
        super(TransactionStore, self).__init__(hs)

        # New transactions that are currently in flights
        self.inflight_transactions = {}

        # Newly delievered transactions that *weren't* persisted while in flight
        self.new_delivered_transactions = {}

        # Newly delivered transactions that *were* persisted while in flight
        self.update_delivered_transactions = {}

        self.last_transaction = {}

        reactor.addSystemEventTrigger("before", "shutdown", self._persist_in_mem_txns)
        hs.get_clock().looping_call(
            self._persist_in_mem_txns,
            1000,
        )

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
            table="received_transactions",
            keyvalues={
                "transaction_id": transaction_id,
                "origin": origin,
            },
            retcols=(
                "transaction_id", "origin", "ts", "response_code", "response_json",
                "has_been_referenced",
            ),
            allow_none=True,
        )

        if result and result["response_code"]:
            return result["response_code"], json.loads(str(result["response_json"]))
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
            table="received_transactions",
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

        auto_id = self._transaction_id_gen.get_next()

        txn_row = _TransactionRow(
            id=auto_id,
            transaction_id=transaction_id,
            destination=destination,
            ts=origin_server_ts,
            response_code=0,
            response_json=None,
        )

        self.inflight_transactions.setdefault(destination, {})[transaction_id] = txn_row

        prev_txn = self.last_transaction.get(destination)
        if prev_txn:
            return defer.succeed(prev_txn)
        else:
            return self.runInteraction(
                "_get_prevs_txn",
                self._get_prevs_txn,
                destination,
            )

    def _get_prevs_txn(self, txn, destination):
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

        return prev_txns

    def delivered_txn(self, transaction_id, destination, code, response_dict):
        """Persists the response for an outgoing transaction.

        Args:
            transaction_id (str)
            destination (str)
            code (int)
            response_json (str)
        """

        txn_row = self.inflight_transactions.get(
            destination, {}
        ).pop(transaction_id, None)

        self.last_transaction[destination] = transaction_id

        if txn_row:
            d = self.new_delivered_transactions.setdefault(destination, {})
            d[transaction_id] = txn_row._replace(
                response_code=code,
                response_json=None,  # For now, don't persist response
            )
        else:
            d = self.update_delivered_transactions.setdefault(destination, {})
            # For now, don't persist response
            d[transaction_id] = _UpdateTransactionRow(code, None)

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
            table="destinations",
            keyvalues={
                "destination": destination,
            },
            retcols=("destination", "retry_last_ts", "retry_interval"),
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

    @defer.inlineCallbacks
    def _persist_in_mem_txns(self):
        try:
            inflight = self.inflight_transactions
            new_delivered = self.new_delivered_transactions
            update_delivered = self.update_delivered_transactions

            self.inflight_transactions = {}
            self.new_delivered_transactions = {}
            self.update_delivered_transactions = {}

            full_rows = [
                row._asdict()
                for txn_map in itertools.chain(inflight.values(), new_delivered.values())
                for row in txn_map.values()
            ]

            def f(txn):
                if full_rows:
                    self._simple_insert_many_txn(
                        txn=txn,
                        table="sent_transactions",
                        values=full_rows
                    )

                for dest, txn_map in update_delivered.items():
                    for txn_id, update_row in txn_map.items():
                        self._simple_update_one_txn(
                            txn,
                            table="sent_transactions",
                            keyvalues={
                                "transaction_id": txn_id,
                                "destination": dest,
                            },
                            updatevalues={
                                "response_code": update_row.response_code,
                                "response_json": None,  # For now, don't persist response
                            }
                        )

            if full_rows or update_delivered:
                yield self.runInteraction("_persist_in_mem_txns", f)
        except:
            logger.exception("Failed to persist transactions!")
