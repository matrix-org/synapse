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

import logging
from collections import namedtuple

from canonicaljson import encode_canonical_json

from twisted.internet import defer

from synapse.metrics.background_process_metrics import run_as_background_process
from synapse.storage._base import SQLBaseStore, db_to_json
from synapse.storage.database import Database
from synapse.util.caches.expiringcache import ExpiringCache

db_binary_type = memoryview

logger = logging.getLogger(__name__)


_TransactionRow = namedtuple(
    "_TransactionRow",
    ("id", "transaction_id", "destination", "ts", "response_code", "response_json"),
)

_UpdateTransactionRow = namedtuple(
    "_TransactionRow", ("response_code", "response_json")
)

SENTINEL = object()


class TransactionStore(SQLBaseStore):
    """A collection of queries for handling PDUs.
    """

    def __init__(self, database: Database, db_conn, hs):
        super(TransactionStore, self).__init__(database, db_conn, hs)

        self._clock.looping_call(self._start_cleanup_transactions, 30 * 60 * 1000)

        self._destination_retry_cache = ExpiringCache(
            cache_name="get_destination_retry_timings",
            clock=self._clock,
            expiry_ms=5 * 60 * 1000,
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

        return self.db.runInteraction(
            "get_received_txn_response",
            self._get_received_txn_response,
            transaction_id,
            origin,
        )

    def _get_received_txn_response(self, txn, transaction_id, origin):
        result = self.db.simple_select_one_txn(
            txn,
            table="received_transactions",
            keyvalues={"transaction_id": transaction_id, "origin": origin},
            retcols=(
                "transaction_id",
                "origin",
                "ts",
                "response_code",
                "response_json",
                "has_been_referenced",
            ),
            allow_none=True,
        )

        if result and result["response_code"]:
            return result["response_code"], db_to_json(result["response_json"])

        else:
            return None

    def set_received_txn_response(self, transaction_id, origin, code, response_dict):
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

        return self.db.simple_insert(
            table="received_transactions",
            values={
                "transaction_id": transaction_id,
                "origin": origin,
                "response_code": code,
                "response_json": db_binary_type(encode_canonical_json(response_dict)),
                "ts": self._clock.time_msec(),
            },
            or_ignore=True,
            desc="set_received_txn_response",
        )

    @defer.inlineCallbacks
    def get_destination_retry_timings(self, destination):
        """Gets the current retry timings (if any) for a given destination.

        Args:
            destination (str)

        Returns:
            None if not retrying
            Otherwise a dict for the retry scheme
        """

        result = self._destination_retry_cache.get(destination, SENTINEL)
        if result is not SENTINEL:
            return result

        result = yield self.db.runInteraction(
            "get_destination_retry_timings",
            self._get_destination_retry_timings,
            destination,
        )

        # We don't hugely care about race conditions between getting and
        # invalidating the cache, since we time out fairly quickly anyway.
        self._destination_retry_cache[destination] = result
        return result

    def _get_destination_retry_timings(self, txn, destination):
        result = self.db.simple_select_one_txn(
            txn,
            table="destinations",
            keyvalues={"destination": destination},
            retcols=("destination", "failure_ts", "retry_last_ts", "retry_interval"),
            allow_none=True,
        )

        if result and result["retry_last_ts"] > 0:
            return result
        else:
            return None

    def set_destination_retry_timings(
        self, destination, failure_ts, retry_last_ts, retry_interval
    ):
        """Sets the current retry timings for a given destination.
        Both timings should be zero if retrying is no longer occuring.

        Args:
            destination (str)
            failure_ts (int|None) - when the server started failing (ms since epoch)
            retry_last_ts (int) - time of last retry attempt in unix epoch ms
            retry_interval (int) - how long until next retry in ms
        """

        self._destination_retry_cache.pop(destination, None)
        return self.db.runInteraction(
            "set_destination_retry_timings",
            self._set_destination_retry_timings,
            destination,
            failure_ts,
            retry_last_ts,
            retry_interval,
        )

    def _set_destination_retry_timings(
        self, txn, destination, failure_ts, retry_last_ts, retry_interval
    ):

        if self.database_engine.can_native_upsert:
            # Upsert retry time interval if retry_interval is zero (i.e. we're
            # resetting it) or greater than the existing retry interval.

            sql = """
                INSERT INTO destinations (
                    destination, failure_ts, retry_last_ts, retry_interval
                )
                    VALUES (?, ?, ?, ?)
                ON CONFLICT (destination) DO UPDATE SET
                        failure_ts = EXCLUDED.failure_ts,
                        retry_last_ts = EXCLUDED.retry_last_ts,
                        retry_interval = EXCLUDED.retry_interval
                    WHERE
                        EXCLUDED.retry_interval = 0
                        OR destinations.retry_interval < EXCLUDED.retry_interval
            """

            txn.execute(sql, (destination, failure_ts, retry_last_ts, retry_interval))

            return

        self.database_engine.lock_table(txn, "destinations")

        # We need to be careful here as the data may have changed from under us
        # due to a worker setting the timings.

        prev_row = self.db.simple_select_one_txn(
            txn,
            table="destinations",
            keyvalues={"destination": destination},
            retcols=("failure_ts", "retry_last_ts", "retry_interval"),
            allow_none=True,
        )

        if not prev_row:
            self.db.simple_insert_txn(
                txn,
                table="destinations",
                values={
                    "destination": destination,
                    "failure_ts": failure_ts,
                    "retry_last_ts": retry_last_ts,
                    "retry_interval": retry_interval,
                },
            )
        elif retry_interval == 0 or prev_row["retry_interval"] < retry_interval:
            self.db.simple_update_one_txn(
                txn,
                "destinations",
                keyvalues={"destination": destination},
                updatevalues={
                    "failure_ts": failure_ts,
                    "retry_last_ts": retry_last_ts,
                    "retry_interval": retry_interval,
                },
            )

    def _start_cleanup_transactions(self):
        return run_as_background_process(
            "cleanup_transactions", self._cleanup_transactions
        )

    def _cleanup_transactions(self):
        now = self._clock.time_msec()
        month_ago = now - 30 * 24 * 60 * 60 * 1000

        def _cleanup_transactions_txn(txn):
            txn.execute("DELETE FROM received_transactions WHERE ts < ?", (month_ago,))

        return self.db.runInteraction(
            "_cleanup_transactions", _cleanup_transactions_txn
        )
