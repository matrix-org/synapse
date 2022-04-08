# Copyright 2016 OpenMarket Ltd
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
from typing import TYPE_CHECKING, Dict, List, Mapping, Optional, Tuple, Union, cast

from typing_extensions import TypedDict

from synapse.metrics.background_process_metrics import wrap_as_background_process
from synapse.storage._base import SQLBaseStore
from synapse.storage.database import (
    DatabasePool,
    LoggingDatabaseConnection,
    LoggingTransaction,
    make_tuple_comparison_clause,
)
from synapse.storage.databases.main.monthly_active_users import (
    MonthlyActiveUsersWorkerStore,
)
from synapse.types import JsonDict, UserID
from synapse.util.caches.lrucache import LruCache

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)

# Number of msec of granularity to store the user IP 'last seen' time. Smaller
# times give more inserts into the database even for readonly API hits
# 120 seconds == 2 minutes
LAST_SEEN_GRANULARITY = 120 * 1000


class DeviceLastConnectionInfo(TypedDict):
    """Metadata for the last connection seen for a user and device combination"""

    # These types must match the columns in the `devices` table
    user_id: str
    device_id: str

    ip: Optional[str]
    user_agent: Optional[str]
    last_seen: Optional[int]


class LastConnectionInfo(TypedDict):
    """Metadata for the last connection seen for an access token and IP combination"""

    # These types must match the columns in the `user_ips` table
    access_token: str
    ip: str

    user_agent: str
    last_seen: int


class ClientIpBackgroundUpdateStore(SQLBaseStore):
    def __init__(
        self,
        database: DatabasePool,
        db_conn: LoggingDatabaseConnection,
        hs: "HomeServer",
    ):
        super().__init__(database, db_conn, hs)

        self.db_pool.updates.register_background_index_update(
            "user_ips_device_index",
            index_name="user_ips_device_id",
            table="user_ips",
            columns=["user_id", "device_id", "last_seen"],
        )

        self.db_pool.updates.register_background_index_update(
            "user_ips_last_seen_index",
            index_name="user_ips_last_seen",
            table="user_ips",
            columns=["user_id", "last_seen"],
        )

        self.db_pool.updates.register_background_index_update(
            "user_ips_last_seen_only_index",
            index_name="user_ips_last_seen_only",
            table="user_ips",
            columns=["last_seen"],
        )

        self.db_pool.updates.register_background_update_handler(
            "user_ips_analyze", self._analyze_user_ip
        )

        self.db_pool.updates.register_background_update_handler(
            "user_ips_remove_dupes", self._remove_user_ip_dupes
        )

        # Register a unique index
        self.db_pool.updates.register_background_index_update(
            "user_ips_device_unique_index",
            index_name="user_ips_user_token_ip_unique_index",
            table="user_ips",
            columns=["user_id", "access_token", "ip"],
            unique=True,
        )

        # Drop the old non-unique index
        self.db_pool.updates.register_background_update_handler(
            "user_ips_drop_nonunique_index", self._remove_user_ip_nonunique
        )

        # Update the last seen info in devices.
        self.db_pool.updates.register_background_update_handler(
            "devices_last_seen", self._devices_last_seen_update
        )

    async def _remove_user_ip_nonunique(
        self, progress: JsonDict, batch_size: int
    ) -> int:
        def f(conn: LoggingDatabaseConnection) -> None:
            txn = conn.cursor()
            txn.execute("DROP INDEX IF EXISTS user_ips_user_ip")
            txn.close()

        await self.db_pool.runWithConnection(f)
        await self.db_pool.updates._end_background_update(
            "user_ips_drop_nonunique_index"
        )
        return 1

    async def _analyze_user_ip(self, progress: JsonDict, batch_size: int) -> int:
        # Background update to analyze user_ips table before we run the
        # deduplication background update. The table may not have been analyzed
        # for ages due to the table locks.
        #
        # This will lock out the naive upserts to user_ips while it happens, but
        # the analyze should be quick (28GB table takes ~10s)
        def user_ips_analyze(txn: LoggingTransaction) -> None:
            txn.execute("ANALYZE user_ips")

        await self.db_pool.runInteraction("user_ips_analyze", user_ips_analyze)

        await self.db_pool.updates._end_background_update("user_ips_analyze")

        return 1

    async def _remove_user_ip_dupes(self, progress: JsonDict, batch_size: int) -> int:
        # This works function works by scanning the user_ips table in batches
        # based on `last_seen`. For each row in a batch it searches the rest of
        # the table to see if there are any duplicates, if there are then they
        # are removed and replaced with a suitable row.

        # Fetch the start of the batch
        begin_last_seen: int = progress.get("last_seen", 0)

        def get_last_seen(txn: LoggingTransaction) -> Optional[int]:
            txn.execute(
                """
                SELECT last_seen FROM user_ips
                WHERE last_seen > ?
                ORDER BY last_seen
                LIMIT 1
                OFFSET ?
                """,
                (begin_last_seen, batch_size),
            )
            row = cast(Optional[Tuple[int]], txn.fetchone())
            if row:
                return row[0]
            else:
                return None

        # Get a last seen that has roughly `batch_size` since `begin_last_seen`
        end_last_seen = await self.db_pool.runInteraction(
            "user_ips_dups_get_last_seen", get_last_seen
        )

        # If it returns None, then we're processing the last batch
        last = end_last_seen is None

        logger.info(
            "Scanning for duplicate 'user_ips' rows in range: %s <= last_seen < %s",
            begin_last_seen,
            end_last_seen,
        )

        def remove(txn: LoggingTransaction) -> None:
            # This works by looking at all entries in the given time span, and
            # then for each (user_id, access_token, ip) tuple in that range
            # checking for any duplicates in the rest of the table (via a join).
            # It then only returns entries which have duplicates, and the max
            # last_seen across all duplicates, which can the be used to delete
            # all other duplicates.
            # It is efficient due to the existence of (user_id, access_token,
            # ip) and (last_seen) indices.

            # Define the search space, which requires handling the last batch in
            # a different way
            args: Tuple[int, ...]
            if last:
                clause = "? <= last_seen"
                args = (begin_last_seen,)
            else:
                assert end_last_seen is not None
                clause = "? <= last_seen AND last_seen < ?"
                args = (begin_last_seen, end_last_seen)

            # (Note: The DISTINCT in the inner query is important to ensure that
            # the COUNT(*) is accurate, otherwise double counting may happen due
            # to the join effectively being a cross product)
            txn.execute(
                """
                SELECT user_id, access_token, ip,
                       MAX(device_id), MAX(user_agent), MAX(last_seen),
                       COUNT(*)
                FROM (
                    SELECT DISTINCT user_id, access_token, ip
                    FROM user_ips
                    WHERE {}
                ) c
                INNER JOIN user_ips USING (user_id, access_token, ip)
                GROUP BY user_id, access_token, ip
                HAVING count(*) > 1
                """.format(
                    clause
                ),
                args,
            )
            res = cast(
                List[Tuple[str, str, str, Optional[str], str, int, int]], txn.fetchall()
            )

            # We've got some duplicates
            for i in res:
                user_id, access_token, ip, device_id, user_agent, last_seen, count = i

                # We want to delete the duplicates so we end up with only a
                # single row.
                #
                # The naive way of doing this would be just to delete all rows
                # and reinsert a constructed row. However, if there are a lot of
                # duplicate rows this can cause the table to grow a lot, which
                # can be problematic in two ways:
                #   1. If user_ips is already large then this can cause the
                #      table to rapidly grow, potentially filling the disk.
                #   2. Reinserting a lot of rows can confuse the table
                #      statistics for postgres, causing it to not use the
                #      correct indices for the query above, resulting in a full
                #      table scan. This is incredibly slow for large tables and
                #      can kill database performance. (This seems to mainly
                #      happen for the last query where the clause is simply `? <
                #      last_seen`)
                #
                # So instead we want to delete all but *one* of the duplicate
                # rows. That is hard to do reliably, so we cheat and do a two
                # step process:
                #   1. Delete all rows with a last_seen strictly less than the
                #      max last_seen. This hopefully results in deleting all but
                #      one row the majority of the time, but there may be
                #      duplicate last_seen
                #   2. If multiple rows remain, we fall back to the naive method
                #      and simply delete all rows and reinsert.
                #
                # Note that this relies on no new duplicate rows being inserted,
                # but if that is happening then this entire process is futile
                # anyway.

                # Do step 1:

                txn.execute(
                    """
                    DELETE FROM user_ips
                    WHERE user_id = ? AND access_token = ? AND ip = ? AND last_seen < ?
                    """,
                    (user_id, access_token, ip, last_seen),
                )
                if txn.rowcount == count - 1:
                    # We deleted all but one of the duplicate rows, i.e. there
                    # is exactly one remaining and so there is nothing left to
                    # do.
                    continue
                elif txn.rowcount >= count:
                    raise Exception(
                        "We deleted more duplicate rows from 'user_ips' than expected"
                    )

                # The previous step didn't delete enough rows, so we fallback to
                # step 2:

                # Drop all the duplicates
                txn.execute(
                    """
                    DELETE FROM user_ips
                    WHERE user_id = ? AND access_token = ? AND ip = ?
                    """,
                    (user_id, access_token, ip),
                )

                # Add in one to be the last_seen
                txn.execute(
                    """
                    INSERT INTO user_ips
                    (user_id, access_token, ip, device_id, user_agent, last_seen)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (user_id, access_token, ip, device_id, user_agent, last_seen),
                )

            self.db_pool.updates._background_update_progress_txn(
                txn, "user_ips_remove_dupes", {"last_seen": end_last_seen}
            )

        await self.db_pool.runInteraction("user_ips_dups_remove", remove)

        if last:
            await self.db_pool.updates._end_background_update("user_ips_remove_dupes")

        return batch_size

    async def _devices_last_seen_update(
        self, progress: JsonDict, batch_size: int
    ) -> int:
        """Background update to insert last seen info into devices table"""

        last_user_id: str = progress.get("last_user_id", "")
        last_device_id: str = progress.get("last_device_id", "")

        def _devices_last_seen_update_txn(txn: LoggingTransaction) -> int:
            # This consists of two queries:
            #
            #   1. The sub-query searches for the next N devices and joins
            #      against user_ips to find the max last_seen associated with
            #      that device.
            #   2. The outer query then joins again against user_ips on
            #      user/device/last_seen. This *should* hopefully only
            #      return one row, but if it does return more than one then
            #      we'll just end up updating the same device row multiple
            #      times, which is fine.

            where_args: List[Union[str, int]]
            where_clause, where_args = make_tuple_comparison_clause(
                [("user_id", last_user_id), ("device_id", last_device_id)],
            )

            sql = """
                SELECT
                    last_seen, ip, user_agent, user_id, device_id
                FROM (
                    SELECT
                        user_id, device_id, MAX(u.last_seen) AS last_seen
                    FROM devices
                    INNER JOIN user_ips AS u USING (user_id, device_id)
                    WHERE %(where_clause)s
                    GROUP BY user_id, device_id
                    ORDER BY user_id ASC, device_id ASC
                    LIMIT ?
                ) c
                INNER JOIN user_ips AS u USING (user_id, device_id, last_seen)
            """ % {
                "where_clause": where_clause
            }
            txn.execute(sql, where_args + [batch_size])

            rows = cast(List[Tuple[int, str, str, str, str]], txn.fetchall())
            if not rows:
                return 0

            sql = """
                UPDATE devices
                SET last_seen = ?, ip = ?, user_agent = ?
                WHERE user_id = ? AND device_id = ?
            """
            txn.execute_batch(sql, rows)

            _, _, _, user_id, device_id = rows[-1]
            self.db_pool.updates._background_update_progress_txn(
                txn,
                "devices_last_seen",
                {"last_user_id": user_id, "last_device_id": device_id},
            )

            return len(rows)

        updated = await self.db_pool.runInteraction(
            "_devices_last_seen_update", _devices_last_seen_update_txn
        )

        if not updated:
            await self.db_pool.updates._end_background_update("devices_last_seen")

        return updated


class ClientIpWorkerStore(ClientIpBackgroundUpdateStore, MonthlyActiveUsersWorkerStore):
    def __init__(
        self,
        database: DatabasePool,
        db_conn: LoggingDatabaseConnection,
        hs: "HomeServer",
    ):
        super().__init__(database, db_conn, hs)

        if hs.config.redis.redis_enabled:
            # If we're using Redis, we can shift this update process off to
            # the background worker
            self._update_on_this_worker = hs.config.worker.run_background_tasks
        else:
            # If we're NOT using Redis, this must be handled by the master
            self._update_on_this_worker = hs.get_instance_name() == "master"

        self.user_ips_max_age = hs.config.server.user_ips_max_age

        # (user_id, access_token, ip,) -> last_seen
        self.client_ip_last_seen = LruCache[Tuple[str, str, str], int](
            cache_name="client_ip_last_seen", max_size=50000
        )

        if hs.config.worker.run_background_tasks and self.user_ips_max_age:
            self._clock.looping_call(self._prune_old_user_ips, 5 * 1000)

        if self._update_on_this_worker:
            # This is the designated worker that can write to the client IP
            # tables.

            # (user_id, access_token, ip,) -> (user_agent, device_id, last_seen)
            self._batch_row_update: Dict[
                Tuple[str, str, str], Tuple[str, Optional[str], int]
            ] = {}

            self._client_ip_looper = self._clock.looping_call(
                self._update_client_ips_batch, 5 * 1000
            )
            self.hs.get_reactor().addSystemEventTrigger(
                "before", "shutdown", self._update_client_ips_batch
            )

    @wrap_as_background_process("prune_old_user_ips")
    async def _prune_old_user_ips(self) -> None:
        """Removes entries in user IPs older than the configured period."""

        if self.user_ips_max_age is None:
            # Nothing to do
            return

        if not await self.db_pool.updates.has_completed_background_update(
            "devices_last_seen"
        ):
            # Only start pruning if we have finished populating the devices
            # last seen info.
            return

        # We do a slightly funky SQL delete to ensure we don't try and delete
        # too much at once (as the table may be very large from before we
        # started pruning).
        #
        # This works by finding the max last_seen that is less than the given
        # time, but has no more than N rows before it, deleting all rows with
        # a lesser last_seen time. (We COALESCE so that the sub-SELECT always
        # returns exactly one row).
        sql = """
            DELETE FROM user_ips
            WHERE last_seen <= (
                SELECT COALESCE(MAX(last_seen), -1)
                FROM (
                    SELECT last_seen FROM user_ips
                    WHERE last_seen <= ?
                    ORDER BY last_seen ASC
                    LIMIT 5000
                ) AS u
            )
        """

        timestamp = self._clock.time_msec() - self.user_ips_max_age

        def _prune_old_user_ips_txn(txn: LoggingTransaction) -> None:
            txn.execute(sql, (timestamp,))

        await self.db_pool.runInteraction(
            "_prune_old_user_ips", _prune_old_user_ips_txn
        )

    async def _get_last_client_ip_by_device_from_database(
        self, user_id: str, device_id: Optional[str]
    ) -> Dict[Tuple[str, str], DeviceLastConnectionInfo]:
        """For each device_id listed, give the user_ip it was last seen on.

        The result might be slightly out of date as client IPs are inserted in batches.

        Args:
            user_id: The user to fetch devices for.
            device_id: If None fetches all devices for the user

        Returns:
            A dictionary mapping a tuple of (user_id, device_id) to dicts, with
            keys giving the column names from the devices table.
        """

        keyvalues = {"user_id": user_id}
        if device_id is not None:
            keyvalues["device_id"] = device_id

        res = cast(
            List[DeviceLastConnectionInfo],
            await self.db_pool.simple_select_list(
                table="devices",
                keyvalues=keyvalues,
                retcols=("user_id", "ip", "user_agent", "device_id", "last_seen"),
            ),
        )

        return {(d["user_id"], d["device_id"]): d for d in res}

    async def _get_user_ip_and_agents_from_database(
        self, user: UserID, since_ts: int = 0
    ) -> List[LastConnectionInfo]:
        """Fetch the IPs and user agents for a user since the given timestamp.

        The result might be slightly out of date as client IPs are inserted in batches.

        Args:
            user: The user for which to fetch IP addresses and user agents.
            since_ts: The timestamp after which to fetch IP addresses and user agents,
                in milliseconds.

        Returns:
            A list of dictionaries, each containing:
             * `access_token`: The access token used.
             * `ip`: The IP address used.
             * `user_agent`: The last user agent seen for this access token and IP
               address combination.
             * `last_seen`: The timestamp at which this access token and IP address
               combination was last seen, in milliseconds.

            Only the latest user agent for each access token and IP address combination
            is available.
        """
        user_id = user.to_string()

        def get_recent(txn: LoggingTransaction) -> List[Tuple[str, str, str, int]]:
            txn.execute(
                """
                SELECT access_token, ip, user_agent, last_seen FROM user_ips
                WHERE last_seen >= ? AND user_id = ?
                ORDER BY last_seen
                DESC
                """,
                (since_ts, user_id),
            )
            return cast(List[Tuple[str, str, str, int]], txn.fetchall())

        rows = await self.db_pool.runInteraction(
            desc="get_user_ip_and_agents", func=get_recent
        )

        return [
            {
                "access_token": access_token,
                "ip": ip,
                "user_agent": user_agent,
                "last_seen": last_seen,
            }
            for access_token, ip, user_agent, last_seen in rows
        ]

    async def insert_client_ip(
        self,
        user_id: str,
        access_token: str,
        ip: str,
        user_agent: str,
        device_id: Optional[str],
        now: Optional[int] = None,
    ) -> None:
        if not now:
            now = int(self._clock.time_msec())
        key = (user_id, access_token, ip)

        try:
            last_seen = self.client_ip_last_seen.get(key)
        except KeyError:
            last_seen = None

        # Rate-limited inserts
        if last_seen is not None and (now - last_seen) < LAST_SEEN_GRANULARITY:
            return

        self.client_ip_last_seen.set(key, now)

        if self._update_on_this_worker:
            await self.populate_monthly_active_users(user_id)
            self._batch_row_update[key] = (user_agent, device_id, now)
        else:
            # We are not the designated writer-worker, so stream over replication
            self.hs.get_replication_command_handler().send_user_ip(
                user_id, access_token, ip, user_agent, device_id, now
            )

    @wrap_as_background_process("update_client_ips")
    async def _update_client_ips_batch(self) -> None:
        assert (
            self._update_on_this_worker
        ), "This worker is not designated to update client IPs"

        # If the DB pool has already terminated, don't try updating
        if not self.db_pool.is_running():
            return

        to_update = self._batch_row_update
        self._batch_row_update = {}

        if to_update:
            await self.db_pool.runInteraction(
                "_update_client_ips_batch", self._update_client_ips_batch_txn, to_update
            )

    def _update_client_ips_batch_txn(
        self,
        txn: LoggingTransaction,
        to_update: Mapping[Tuple[str, str, str], Tuple[str, Optional[str], int]],
    ) -> None:
        assert (
            self._update_on_this_worker
        ), "This worker is not designated to update client IPs"

        # Keys and values for the `user_ips` upsert.
        user_ips_keys = []
        user_ips_values = []

        # Keys and values for the `devices` update.
        devices_keys = []
        devices_values = []

        for entry in to_update.items():
            (user_id, access_token, ip), (user_agent, device_id, last_seen) = entry
            user_ips_keys.append((user_id, access_token, ip))
            user_ips_values.append((user_agent, device_id, last_seen))

            # Technically an access token might not be associated with
            # a device so we need to check.
            if device_id:
                devices_keys.append((user_id, device_id))
                devices_values.append((user_agent, last_seen, ip))

        self.db_pool.simple_upsert_many_txn(
            txn,
            table="user_ips",
            key_names=("user_id", "access_token", "ip"),
            key_values=user_ips_keys,
            value_names=("user_agent", "device_id", "last_seen"),
            value_values=user_ips_values,
        )

        if devices_values:
            self.db_pool.simple_update_many_txn(
                txn,
                table="devices",
                key_names=("user_id", "device_id"),
                key_values=devices_keys,
                value_names=("user_agent", "last_seen", "ip"),
                value_values=devices_values,
            )

    async def get_last_client_ip_by_device(
        self, user_id: str, device_id: Optional[str]
    ) -> Dict[Tuple[str, str], DeviceLastConnectionInfo]:
        """For each device_id listed, give the user_ip it was last seen on

        Args:
            user_id: The user to fetch devices for.
            device_id: If None fetches all devices for the user

        Returns:
            A dictionary mapping a tuple of (user_id, device_id) to dicts, with
            keys giving the column names from the devices table.
        """
        ret = await self._get_last_client_ip_by_device_from_database(user_id, device_id)

        if not self._update_on_this_worker:
            # Only the writing-worker has additional in-memory data to enhance
            # the result
            return ret

        # Update what is retrieved from the database with data which is pending
        # insertion, as if it has already been stored in the database.
        for key in self._batch_row_update:
            uid, _access_token, ip = key
            if uid == user_id:
                user_agent, did, last_seen = self._batch_row_update[key]

                if did is None:
                    # These updates don't make it to the `devices` table
                    continue

                if not device_id or did == device_id:
                    ret[(user_id, did)] = {
                        "user_id": user_id,
                        "ip": ip,
                        "user_agent": user_agent,
                        "device_id": did,
                        "last_seen": last_seen,
                    }
        return ret

    async def get_user_ip_and_agents(
        self, user: UserID, since_ts: int = 0
    ) -> List[LastConnectionInfo]:
        """Fetch the IPs and user agents for a user since the given timestamp.

        Args:
            user: The user for which to fetch IP addresses and user agents.
            since_ts: The timestamp after which to fetch IP addresses and user agents,
                in milliseconds.

        Returns:
            A list of dictionaries, each containing:
             * `access_token`: The access token used.
             * `ip`: The IP address used.
             * `user_agent`: The last user agent seen for this access token and IP
               address combination.
             * `last_seen`: The timestamp at which this access token and IP address
               combination was last seen, in milliseconds.

            Only the latest user agent for each access token and IP address combination
            is available.
        """
        rows_from_db = await self._get_user_ip_and_agents_from_database(user, since_ts)

        if not self._update_on_this_worker:
            # Only the writing-worker has additional in-memory data to enhance
            # the result
            return rows_from_db

        results: Dict[Tuple[str, str], LastConnectionInfo] = {
            (connection["access_token"], connection["ip"]): connection
            for connection in rows_from_db
        }

        # Overlay data that is pending insertion on top of the results from the
        # database.
        user_id = user.to_string()
        for key in self._batch_row_update:
            uid, access_token, ip = key
            if uid == user_id:
                user_agent, _, last_seen = self._batch_row_update[key]
                if last_seen >= since_ts:
                    results[(access_token, ip)] = {
                        "access_token": access_token,
                        "ip": ip,
                        "user_agent": user_agent,
                        "last_seen": last_seen,
                    }

        return list(results.values())
