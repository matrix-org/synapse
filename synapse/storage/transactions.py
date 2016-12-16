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

from twisted.internet import defer

from canonicaljson import encode_canonical_json

from collections import namedtuple

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

        self._clock.looping_call(self._cleanup_transactions, 30 * 60 * 1000)

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
                "ts": self._clock.time_msec(),
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
        return defer.succeed([])

    def delivered_txn(self, transaction_id, destination, code, response_dict):
        """Persists the response for an outgoing transaction.

        Args:
            transaction_id (str)
            destination (str)
            code (int)
            response_json (str)
        """
        pass

    @cached(max_entries=10000)
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
        self.database_engine.lock_table(txn, "destinations")

        self._invalidate_cache_and_stream(
            txn, self.get_destination_retry_timings, (destination,)
        )

        # We need to be careful here as the data may have changed from under us
        # due to a worker setting the timings.

        prev_row = self._simple_select_one_txn(
            txn,
            table="destinations",
            keyvalues={
                "destination": destination,
            },
            retcols=("retry_last_ts", "retry_interval"),
            allow_none=True,
        )

        if not prev_row:
            self._simple_insert_txn(
                txn,
                table="destinations",
                values={
                    "destination": destination,
                    "retry_last_ts": retry_last_ts,
                    "retry_interval": retry_interval,
                }
            )
        elif retry_interval == 0 or prev_row["retry_interval"] < retry_interval:
            self._simple_update_one_txn(
                txn,
                "destinations",
                keyvalues={
                    "destination": destination,
                },
                updatevalues={
                    "retry_last_ts": retry_last_ts,
                    "retry_interval": retry_interval,
                },
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

    def _cleanup_transactions(self):
        now = self._clock.time_msec()
        month_ago = now - 30 * 24 * 60 * 60 * 1000

        def _cleanup_transactions_txn(txn):
            txn.execute("DELETE FROM received_transactions WHERE ts < ?", (month_ago,))

        return self.runInteraction("_cleanup_transactions", _cleanup_transactions_txn)
