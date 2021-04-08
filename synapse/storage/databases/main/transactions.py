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
from typing import Iterable, List, Optional, Tuple

from canonicaljson import encode_canonical_json

from synapse.metrics.background_process_metrics import wrap_as_background_process
from synapse.storage._base import SQLBaseStore, db_to_json
from synapse.storage.database import DatabasePool, LoggingTransaction
from synapse.types import JsonDict
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


class TransactionWorkerStore(SQLBaseStore):
    def __init__(self, database: DatabasePool, db_conn, hs):
        super().__init__(database, db_conn, hs)

        if hs.config.run_background_tasks:
            self._clock.looping_call(self._cleanup_transactions, 30 * 60 * 1000)

    @wrap_as_background_process("cleanup_transactions")
    async def _cleanup_transactions(self) -> None:
        now = self._clock.time_msec()
        month_ago = now - 30 * 24 * 60 * 60 * 1000

        def _cleanup_transactions_txn(txn):
            txn.execute("DELETE FROM received_transactions WHERE ts < ?", (month_ago,))

        await self.db_pool.runInteraction(
            "_cleanup_transactions", _cleanup_transactions_txn
        )


class TransactionStore(TransactionWorkerStore):
    """A collection of queries for handling PDUs."""

    def __init__(self, database: DatabasePool, db_conn, hs):
        super().__init__(database, db_conn, hs)

        self._destination_retry_cache = ExpiringCache(
            cache_name="get_destination_retry_timings",
            clock=self._clock,
            expiry_ms=5 * 60 * 1000,
        )

    async def get_received_txn_response(
        self, transaction_id: str, origin: str
    ) -> Optional[Tuple[int, JsonDict]]:
        """For an incoming transaction from a given origin, check if we have
        already responded to it. If so, return the response code and response
        body (as a dict).

        Args:
            transaction_id
            origin

        Returns:
            None if we have not previously responded to this transaction or a
            2-tuple of (int, dict)
        """

        return await self.db_pool.runInteraction(
            "get_received_txn_response",
            self._get_received_txn_response,
            transaction_id,
            origin,
        )

    def _get_received_txn_response(self, txn, transaction_id, origin):
        result = self.db_pool.simple_select_one_txn(
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

    async def set_received_txn_response(
        self, transaction_id: str, origin: str, code: int, response_dict: JsonDict
    ) -> None:
        """Persist the response we returned for an incoming transaction, and
        should return for subsequent transactions with the same transaction_id
        and origin.

        Args:
            transaction_id: The incoming transaction ID.
            origin: The origin server.
            code: The response code.
            response_dict: The response, to be encoded into JSON.
        """

        await self.db_pool.simple_insert(
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

    async def get_destination_retry_timings(self, destination):
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

        result = await self.db_pool.runInteraction(
            "get_destination_retry_timings",
            self._get_destination_retry_timings,
            destination,
        )

        # We don't hugely care about race conditions between getting and
        # invalidating the cache, since we time out fairly quickly anyway.
        self._destination_retry_cache[destination] = result
        return result

    def _get_destination_retry_timings(self, txn, destination):
        result = self.db_pool.simple_select_one_txn(
            txn,
            table="destinations",
            keyvalues={"destination": destination},
            retcols=("destination", "failure_ts", "retry_last_ts", "retry_interval"),
            allow_none=True,
        )

        # check we have a row and retry_last_ts is not null or zero
        # (retry_last_ts can't be negative)
        if result and result["retry_last_ts"]:
            return result
        else:
            return None

    async def set_destination_retry_timings(
        self,
        destination: str,
        failure_ts: Optional[int],
        retry_last_ts: int,
        retry_interval: int,
    ) -> None:
        """Sets the current retry timings for a given destination.
        Both timings should be zero if retrying is no longer occurring.

        Args:
            destination
            failure_ts: when the server started failing (ms since epoch)
            retry_last_ts: time of last retry attempt in unix epoch ms
            retry_interval: how long until next retry in ms
        """

        self._destination_retry_cache.pop(destination, None)
        if self.database_engine.can_native_upsert:
            return await self.db_pool.runInteraction(
                "set_destination_retry_timings",
                self._set_destination_retry_timings_native,
                destination,
                failure_ts,
                retry_last_ts,
                retry_interval,
                db_autocommit=True,  # Safe as its a single upsert
            )
        else:
            return await self.db_pool.runInteraction(
                "set_destination_retry_timings",
                self._set_destination_retry_timings_emulated,
                destination,
                failure_ts,
                retry_last_ts,
                retry_interval,
            )

    def _set_destination_retry_timings_native(
        self, txn, destination, failure_ts, retry_last_ts, retry_interval
    ):
        assert self.database_engine.can_native_upsert

        # Upsert retry time interval if retry_interval is zero (i.e. we're
        # resetting it) or greater than the existing retry interval.
        #
        # WARNING: This is executed in autocommit, so we shouldn't add any more
        # SQL calls in here (without being very careful).
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
                    OR destinations.retry_interval IS NULL
                    OR destinations.retry_interval < EXCLUDED.retry_interval
        """

        txn.execute(sql, (destination, failure_ts, retry_last_ts, retry_interval))

    def _set_destination_retry_timings_emulated(
        self, txn, destination, failure_ts, retry_last_ts, retry_interval
    ):
        self.database_engine.lock_table(txn, "destinations")

        # We need to be careful here as the data may have changed from under us
        # due to a worker setting the timings.

        prev_row = self.db_pool.simple_select_one_txn(
            txn,
            table="destinations",
            keyvalues={"destination": destination},
            retcols=("failure_ts", "retry_last_ts", "retry_interval"),
            allow_none=True,
        )

        if not prev_row:
            self.db_pool.simple_insert_txn(
                txn,
                table="destinations",
                values={
                    "destination": destination,
                    "failure_ts": failure_ts,
                    "retry_last_ts": retry_last_ts,
                    "retry_interval": retry_interval,
                },
            )
        elif (
            retry_interval == 0
            or prev_row["retry_interval"] is None
            or prev_row["retry_interval"] < retry_interval
        ):
            self.db_pool.simple_update_one_txn(
                txn,
                "destinations",
                keyvalues={"destination": destination},
                updatevalues={
                    "failure_ts": failure_ts,
                    "retry_last_ts": retry_last_ts,
                    "retry_interval": retry_interval,
                },
            )

    async def store_destination_rooms_entries(
        self,
        destinations: Iterable[str],
        room_id: str,
        stream_ordering: int,
    ) -> None:
        """
        Updates or creates `destination_rooms` entries in batch for a single event.

        Args:
            destinations: list of destinations
            room_id: the room_id of the event
            stream_ordering: the stream_ordering of the event
        """

        await self.db_pool.simple_upsert_many(
            table="destinations",
            key_names=("destination",),
            key_values=[(d,) for d in destinations],
            value_names=[],
            value_values=[],
            desc="store_destination_rooms_entries_dests",
        )

        rows = [(destination, room_id) for destination in destinations]
        await self.db_pool.simple_upsert_many(
            table="destination_rooms",
            key_names=("destination", "room_id"),
            key_values=rows,
            value_names=["stream_ordering"],
            value_values=[(stream_ordering,)] * len(rows),
            desc="store_destination_rooms_entries_rooms",
        )

    async def get_destination_last_successful_stream_ordering(
        self, destination: str
    ) -> Optional[int]:
        """
        Gets the stream ordering of the PDU most-recently successfully sent
        to the specified destination, or None if this information has not been
        tracked yet.

        Args:
            destination: the destination to query
        """
        return await self.db_pool.simple_select_one_onecol(
            "destinations",
            {"destination": destination},
            "last_successful_stream_ordering",
            allow_none=True,
            desc="get_last_successful_stream_ordering",
        )

    async def set_destination_last_successful_stream_ordering(
        self, destination: str, last_successful_stream_ordering: int
    ) -> None:
        """
        Marks that we have successfully sent the PDUs up to and including the
        one specified.

        Args:
            destination: the destination we have successfully sent to
            last_successful_stream_ordering: the stream_ordering of the most
                recent successfully-sent PDU
        """
        return await self.db_pool.simple_upsert(
            "destinations",
            keyvalues={"destination": destination},
            values={"last_successful_stream_ordering": last_successful_stream_ordering},
            desc="set_last_successful_stream_ordering",
        )

    async def get_catch_up_room_event_ids(
        self,
        destination: str,
        last_successful_stream_ordering: int,
    ) -> List[str]:
        """
        Returns at most 50 event IDs and their corresponding stream_orderings
        that correspond to the oldest events that have not yet been sent to
        the destination.

        Args:
            destination: the destination in question
            last_successful_stream_ordering: the stream_ordering of the
                most-recently successfully-transmitted event to the destination

        Returns:
            list of event_ids
        """
        return await self.db_pool.runInteraction(
            "get_catch_up_room_event_ids",
            self._get_catch_up_room_event_ids_txn,
            destination,
            last_successful_stream_ordering,
        )

    @staticmethod
    def _get_catch_up_room_event_ids_txn(
        txn: LoggingTransaction,
        destination: str,
        last_successful_stream_ordering: int,
    ) -> List[str]:
        q = """
                SELECT event_id FROM destination_rooms
                 JOIN events USING (stream_ordering)
                WHERE destination = ?
                  AND stream_ordering > ?
                ORDER BY stream_ordering
                LIMIT 50
            """
        txn.execute(
            q,
            (destination, last_successful_stream_ordering),
        )
        event_ids = [row[0] for row in txn]
        return event_ids

    async def get_catch_up_outstanding_destinations(
        self, after_destination: Optional[str]
    ) -> List[str]:
        """
        Gets at most 25 destinations which have outstanding PDUs to be caught up,
        and are not being backed off from
        Args:
            after_destination:
                If provided, all destinations must be lexicographically greater
                than this one.

        Returns:
            list of up to 25 destinations with outstanding catch-up.
                These are the lexicographically first destinations which are
                lexicographically greater than after_destination (if provided).
        """
        time = self.hs.get_clock().time_msec()

        return await self.db_pool.runInteraction(
            "get_catch_up_outstanding_destinations",
            self._get_catch_up_outstanding_destinations_txn,
            time,
            after_destination,
        )

    @staticmethod
    def _get_catch_up_outstanding_destinations_txn(
        txn: LoggingTransaction, now_time_ms: int, after_destination: Optional[str]
    ) -> List[str]:
        q = """
            SELECT DISTINCT destination FROM destinations
            INNER JOIN destination_rooms USING (destination)
                WHERE
                    stream_ordering > last_successful_stream_ordering
                    AND destination > ?
                    AND (
                        retry_last_ts IS NULL OR
                        retry_last_ts + retry_interval < ?
                    )
                    ORDER BY destination
                    LIMIT 25
        """
        txn.execute(
            q,
            (
                # everything is lexicographically greater than "" so this gives
                # us the first batch of up to 25.
                after_destination or "",
                now_time_ms,
            ),
        )

        destinations = [row[0] for row in txn]
        return destinations
