# -*- coding: utf-8 -*-
# Copyright 2020 The Matrix.org Foundation C.I.C.
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
import typing
from collections import Counter

from twisted.internet import defer

from synapse.metrics import BucketCollector
from synapse.metrics.background_process_metrics import run_as_background_process
from synapse.storage._base import SQLBaseStore
from synapse.storage.data_stores.main.event_push_actions import (
    EventPushActionsWorkerStore,
)
from synapse.storage.database import Database


class ServerMetricsStore(EventPushActionsWorkerStore, SQLBaseStore):
    """Functions to pull various metrics from the DB, for e.g. phone home
    stats and prometheus metrics.
    """

    def __init__(self, database: Database, db_conn, hs):
        super().__init__(database, db_conn, hs)

        # Collect metrics on the number of forward extremities that exist.
        # Counter of number of extremities to count
        self._current_forward_extremities_amount = (
            Counter()
        )  # type: typing.Counter[int]

        BucketCollector(
            "synapse_forward_extremities",
            lambda: self._current_forward_extremities_amount,
            buckets=[1, 2, 3, 5, 7, 10, 15, 20, 50, 100, 200, 500, "+Inf"],
        )

        # Read the extrems every 60 minutes
        def read_forward_extremities():
            # run as a background process to make sure that the database transactions
            # have a logcontext to report to
            return run_as_background_process(
                "read_forward_extremities", self._read_forward_extremities
            )

        hs.get_clock().looping_call(read_forward_extremities, 60 * 60 * 1000)

    async def _read_forward_extremities(self):
        def fetch(txn):
            txn.execute(
                """
                select count(*) c from event_forward_extremities
                group by room_id
                """
            )
            return txn.fetchall()

        res = await self.db.runInteraction("read_forward_extremities", fetch)
        self._current_forward_extremities_amount = Counter([x[0] for x in res])

    @defer.inlineCallbacks
    def count_daily_messages(self):
        """
        Returns an estimate of the number of messages sent in the last day.

        If it has been significantly less or more than one day since the last
        call to this function, it will return None.
        """

        def _count_messages(txn):
            sql = """
                SELECT COALESCE(COUNT(*), 0) FROM events
                WHERE type = 'm.room.message'
                AND stream_ordering > ?
            """
            txn.execute(sql, (self.stream_ordering_day_ago,))
            (count,) = txn.fetchone()
            return count

        ret = yield self.db.runInteraction("count_messages", _count_messages)
        return ret

    @defer.inlineCallbacks
    def count_daily_sent_messages(self):
        def _count_messages(txn):
            # This is good enough as if you have silly characters in your own
            # hostname then thats your own fault.
            like_clause = "%:" + self.hs.hostname

            sql = """
                SELECT COALESCE(COUNT(*), 0) FROM events
                WHERE type = 'm.room.message'
                    AND sender LIKE ?
                AND stream_ordering > ?
            """

            txn.execute(sql, (like_clause, self.stream_ordering_day_ago))
            (count,) = txn.fetchone()
            return count

        ret = yield self.db.runInteraction("count_daily_sent_messages", _count_messages)
        return ret

    @defer.inlineCallbacks
    def count_daily_active_rooms(self):
        def _count(txn):
            sql = """
                SELECT COALESCE(COUNT(DISTINCT room_id), 0) FROM events
                WHERE type = 'm.room.message'
                AND stream_ordering > ?
            """
            txn.execute(sql, (self.stream_ordering_day_ago,))
            (count,) = txn.fetchone()
            return count

        ret = yield self.db.runInteraction("count_daily_active_rooms", _count)
        return ret
