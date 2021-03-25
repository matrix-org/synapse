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
import calendar
import logging
import time
from typing import Dict

from synapse.metrics import GaugeBucketCollector
from synapse.metrics.background_process_metrics import wrap_as_background_process
from synapse.storage._base import SQLBaseStore
from synapse.storage.database import DatabasePool
from synapse.storage.databases.main.event_push_actions import (
    EventPushActionsWorkerStore,
)

logger = logging.getLogger(__name__)

# Collect metrics on the number of forward extremities that exist.
_extremities_collecter = GaugeBucketCollector(
    "synapse_forward_extremities",
    "Number of rooms on the server with the given number of forward extremities"
    " or fewer",
    buckets=[1, 2, 3, 5, 7, 10, 15, 20, 50, 100, 200, 500],
)

# we also expose metrics on the "number of excess extremity events", which is
# (E-1)*N, where E is the number of extremities and N is the number of state
# events in the room. This is an approximation to the number of state events
# we could remove from state resolution by reducing the graph to a single
# forward extremity.
_excess_state_events_collecter = GaugeBucketCollector(
    "synapse_excess_extremity_events",
    "Number of rooms on the server with the given number of excess extremity "
    "events, or fewer",
    buckets=[0] + [1 << n for n in range(12)],
)


class ServerMetricsStore(EventPushActionsWorkerStore, SQLBaseStore):
    """Functions to pull various metrics from the DB, for e.g. phone home
    stats and prometheus metrics.
    """

    def __init__(self, database: DatabasePool, db_conn, hs):
        super().__init__(database, db_conn, hs)

        # Read the extrems every 60 minutes
        if hs.config.run_background_tasks:
            self._clock.looping_call(self._read_forward_extremities, 60 * 60 * 1000)

        # Used in _generate_user_daily_visits to keep track of progress
        self._last_user_visit_update = self._get_start_of_day()

    @wrap_as_background_process("read_forward_extremities")
    async def _read_forward_extremities(self):
        def fetch(txn):
            txn.execute(
                """
                SELECT t1.c, t2.c
                FROM (
                    SELECT room_id, COUNT(*) c FROM event_forward_extremities
                    GROUP BY room_id
                ) t1 LEFT JOIN (
                    SELECT room_id, COUNT(*) c FROM current_state_events
                    GROUP BY room_id
                ) t2 ON t1.room_id = t2.room_id
                """
            )
            return txn.fetchall()

        res = await self.db_pool.runInteraction("read_forward_extremities", fetch)

        _extremities_collecter.update_data(x[0] for x in res)

        _excess_state_events_collecter.update_data(
            (x[0] - 1) * x[1] for x in res if x[1]
        )

    async def count_daily_e2ee_messages(self):
        """
        Returns an estimate of the number of messages sent in the last day.

        If it has been significantly less or more than one day since the last
        call to this function, it will return None.
        """

        def _count_messages(txn):
            sql = """
                SELECT COALESCE(COUNT(*), 0) FROM events
                WHERE type = 'm.room.encrypted'
                AND stream_ordering > ?
            """
            txn.execute(sql, (self.stream_ordering_day_ago,))
            (count,) = txn.fetchone()
            return count

        return await self.db_pool.runInteraction("count_e2ee_messages", _count_messages)

    async def count_daily_sent_e2ee_messages(self):
        def _count_messages(txn):
            # This is good enough as if you have silly characters in your own
            # hostname then that's your own fault.
            like_clause = "%:" + self.hs.hostname

            sql = """
                SELECT COALESCE(COUNT(*), 0) FROM events
                WHERE type = 'm.room.encrypted'
                    AND sender LIKE ?
                AND stream_ordering > ?
            """

            txn.execute(sql, (like_clause, self.stream_ordering_day_ago))
            (count,) = txn.fetchone()
            return count

        return await self.db_pool.runInteraction(
            "count_daily_sent_e2ee_messages", _count_messages
        )

    async def count_daily_active_e2ee_rooms(self):
        def _count(txn):
            sql = """
                SELECT COALESCE(COUNT(DISTINCT room_id), 0) FROM events
                WHERE type = 'm.room.encrypted'
                AND stream_ordering > ?
            """
            txn.execute(sql, (self.stream_ordering_day_ago,))
            (count,) = txn.fetchone()
            return count

        return await self.db_pool.runInteraction(
            "count_daily_active_e2ee_rooms", _count
        )

    async def count_daily_messages(self):
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

        return await self.db_pool.runInteraction("count_messages", _count_messages)

    async def count_daily_sent_messages(self):
        def _count_messages(txn):
            # This is good enough as if you have silly characters in your own
            # hostname then that's your own fault.
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

        return await self.db_pool.runInteraction(
            "count_daily_sent_messages", _count_messages
        )

    async def count_daily_active_rooms(self):
        def _count(txn):
            sql = """
                SELECT COALESCE(COUNT(DISTINCT room_id), 0) FROM events
                WHERE type = 'm.room.message'
                AND stream_ordering > ?
            """
            txn.execute(sql, (self.stream_ordering_day_ago,))
            (count,) = txn.fetchone()
            return count

        return await self.db_pool.runInteraction("count_daily_active_rooms", _count)

    async def count_daily_users(self) -> int:
        """
        Counts the number of users who used this homeserver in the last 24 hours.
        """
        yesterday = int(self._clock.time_msec()) - (1000 * 60 * 60 * 24)
        return await self.db_pool.runInteraction(
            "count_daily_users", self._count_users, yesterday
        )

    async def count_monthly_users(self) -> int:
        """
        Counts the number of users who used this homeserver in the last 30 days.
        Note this method is intended for phonehome metrics only and is different
        from the mau figure in synapse.storage.monthly_active_users which,
        amongst other things, includes a 3 day grace period before a user counts.
        """
        thirty_days_ago = int(self._clock.time_msec()) - (1000 * 60 * 60 * 24 * 30)
        return await self.db_pool.runInteraction(
            "count_monthly_users", self._count_users, thirty_days_ago
        )

    def _count_users(self, txn, time_from):
        """
        Returns number of users seen in the past time_from period
        """
        sql = """
            SELECT COALESCE(count(*), 0) FROM (
                SELECT user_id FROM user_ips
                WHERE last_seen > ?
                GROUP BY user_id
            ) u
        """
        txn.execute(sql, (time_from,))
        (count,) = txn.fetchone()
        return count

    async def count_r30_users(self) -> Dict[str, int]:
        """
        Counts the number of 30 day retained users, defined as:-
         * Users who have created their accounts more than 30 days ago
         * Where last seen at most 30 days ago
         * Where account creation and last_seen are > 30 days apart

        Returns:
             A mapping of counts globally as well as broken out by platform.
        """

        def _count_r30_users(txn):
            thirty_days_in_secs = 86400 * 30
            now = int(self._clock.time())
            thirty_days_ago_in_secs = now - thirty_days_in_secs

            sql = """
                SELECT platform, COALESCE(count(*), 0) FROM (
                     SELECT
                        users.name, platform, users.creation_ts * 1000,
                        MAX(uip.last_seen)
                     FROM users
                     INNER JOIN (
                         SELECT
                         user_id,
                         last_seen,
                         CASE
                             WHEN user_agent LIKE '%%Android%%' THEN 'android'
                             WHEN user_agent LIKE '%%iOS%%' THEN 'ios'
                             WHEN user_agent LIKE '%%Electron%%' THEN 'electron'
                             WHEN user_agent LIKE '%%Mozilla%%' THEN 'web'
                             WHEN user_agent LIKE '%%Gecko%%' THEN 'web'
                             ELSE 'unknown'
                         END
                         AS platform
                         FROM user_ips
                     ) uip
                     ON users.name = uip.user_id
                     AND users.appservice_id is NULL
                     AND users.creation_ts < ?
                     AND uip.last_seen/1000 > ?
                     AND (uip.last_seen/1000) - users.creation_ts > 86400 * 30
                     GROUP BY users.name, platform, users.creation_ts
                ) u GROUP BY platform
            """

            results = {}
            txn.execute(sql, (thirty_days_ago_in_secs, thirty_days_ago_in_secs))

            for row in txn:
                if row[0] == "unknown":
                    pass
                results[row[0]] = row[1]

            sql = """
                SELECT COALESCE(count(*), 0) FROM (
                    SELECT users.name, users.creation_ts * 1000,
                                                        MAX(uip.last_seen)
                    FROM users
                    INNER JOIN (
                        SELECT
                        user_id,
                        last_seen
                        FROM user_ips
                    ) uip
                    ON users.name = uip.user_id
                    AND appservice_id is NULL
                    AND users.creation_ts < ?
                    AND uip.last_seen/1000 > ?
                    AND (uip.last_seen/1000) - users.creation_ts > 86400 * 30
                    GROUP BY users.name, users.creation_ts
                ) u
            """

            txn.execute(sql, (thirty_days_ago_in_secs, thirty_days_ago_in_secs))

            (count,) = txn.fetchone()
            results["all"] = count

            return results

        return await self.db_pool.runInteraction("count_r30_users", _count_r30_users)

    def _get_start_of_day(self):
        """
        Returns millisecond unixtime for start of UTC day.
        """
        now = time.gmtime()
        today_start = calendar.timegm((now.tm_year, now.tm_mon, now.tm_mday, 0, 0, 0))
        return today_start * 1000

    @wrap_as_background_process("generate_user_daily_visits")
    async def generate_user_daily_visits(self) -> None:
        """
        Generates daily visit data for use in cohort/ retention analysis
        """

        def _generate_user_daily_visits(txn):
            logger.info("Calling _generate_user_daily_visits")
            today_start = self._get_start_of_day()
            a_day_in_milliseconds = 24 * 60 * 60 * 1000
            now = self._clock.time_msec()

            # A note on user_agent. Technically a given device can have multiple
            # user agents, so we need to decide which one to pick. We could have
            # handled this in number of ways, but given that we don't care
            # _that_ much we have gone for MAX(). For more details of the other
            # options considered see
            # https://github.com/matrix-org/synapse/pull/8503#discussion_r502306111
            sql = """
                INSERT INTO user_daily_visits (user_id, device_id, timestamp, user_agent)
                    SELECT u.user_id, u.device_id, ?, MAX(u.user_agent)
                    FROM user_ips AS u
                    LEFT JOIN (
                      SELECT user_id, device_id, timestamp FROM user_daily_visits
                      WHERE timestamp = ?
                    ) udv
                    ON u.user_id = udv.user_id AND u.device_id=udv.device_id
                    INNER JOIN users ON users.name=u.user_id
                    WHERE last_seen > ? AND last_seen <= ?
                    AND udv.timestamp IS NULL AND users.is_guest=0
                    AND users.appservice_id IS NULL
                    GROUP BY u.user_id, u.device_id
            """

            # This means that the day has rolled over but there could still
            # be entries from the previous day. There is an edge case
            # where if the user logs in at 23:59 and overwrites their
            # last_seen at 00:01 then they will not be counted in the
            # previous day's stats - it is important that the query is run
            # often to minimise this case.
            if today_start > self._last_user_visit_update:
                yesterday_start = today_start - a_day_in_milliseconds
                txn.execute(
                    sql,
                    (
                        yesterday_start,
                        yesterday_start,
                        self._last_user_visit_update,
                        today_start,
                    ),
                )
                self._last_user_visit_update = today_start

            txn.execute(
                sql, (today_start, today_start, self._last_user_visit_update, now)
            )
            # Update _last_user_visit_update to now. The reason to do this
            # rather just clamping to the beginning of the day is to limit
            # the size of the join - meaning that the query can be run more
            # frequently
            self._last_user_visit_update = now

        await self.db_pool.runInteraction(
            "generate_user_daily_visits", _generate_user_daily_visits
        )
