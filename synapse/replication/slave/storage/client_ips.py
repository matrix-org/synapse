# Copyright 2017 Vector Creations Ltd
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
import abc
import logging
from typing import TYPE_CHECKING, Dict, Mapping, Optional, Tuple

from synapse.metrics.background_process_metrics import wrap_as_background_process
from synapse.storage.database import DatabasePool, LoggingTransaction
from synapse.storage.databases.main.client_ips import LAST_SEEN_GRANULARITY
from synapse.util.caches.lrucache import LruCache

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


class AbstractClientIpStrategy(abc.ABC):
    """
    Abstract interface for the operations that a store should be able to provide
    for dealing with client IPs.

    See `DatabaseWritingClientIpStrategy` (the single writer)
    and `ReplicationStreamingClientIpStrategy` (the
    """

    async def insert_client_ip(
        self, user_id: str, access_token: str, ip: str, user_agent: str, device_id: str
    ) -> None:
        """
        Insert a client IP.

        TODO docstring
        """
        ...


class DatabaseWritingClientIpStrategy(AbstractClientIpStrategy):
    """
    Strategy for writing client IPs by direct database access.
    This is intended to be used on a single designated Synapse worker
    (the background worker).
    """

    def __init__(
        self,
        db_pool: DatabasePool,
        hs: "HomeServer",
    ) -> None:
        assert (
            hs.config.worker.run_background_tasks
        ), "This worker is not designated to update client IPs"

        self._clock = hs.get_clock()
        self._store = hs.get_datastores().main
        self._db_pool = db_pool

        # This is the designated worker that can write to the client IP
        # tables.

        # (user_id, access_token, ip,) -> last_seen
        self.client_ip_last_seen = LruCache[Tuple[str, str, str], int](
            cache_name="client_ip_last_seen", max_size=50000
        )

        # (user_id, access_token, ip,) -> (user_agent, device_id, last_seen)
        self._batch_row_update: Dict[
            Tuple[str, str, str], Tuple[str, Optional[str], int]
        ] = {}

        self._client_ip_looper = self._clock.looping_call(
            self._update_client_ips_batch, 5 * 1000
        )
        hs.get_reactor().addSystemEventTrigger(
            "before", "shutdown", self._update_client_ips_batch
        )

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
        await self._store.populate_monthly_active_users(user_id)
        # Rate-limited inserts
        if last_seen is not None and (now - last_seen) < LAST_SEEN_GRANULARITY:
            return

        self.client_ip_last_seen.set(key, now)

        self._batch_row_update[key] = (user_agent, device_id, now)

    @wrap_as_background_process("update_client_ips")
    async def _update_client_ips_batch(self) -> None:
        # If the DB pool has already terminated, don't try updating
        if not self._db_pool.is_running():
            return

        to_update = self._batch_row_update
        self._batch_row_update = {}

        await self._db_pool.runInteraction(
            "_update_client_ips_batch", self._update_client_ips_batch_txn, to_update
        )

    def _update_client_ips_batch_txn(
        self,
        txn: LoggingTransaction,
        to_update: Mapping[Tuple[str, str, str], Tuple[str, Optional[str], int]],
    ) -> None:
        db_pool = self._db_pool
        if "user_ips" in db_pool._unsafe_to_upsert_tables or (
            not db_pool.engine.can_native_upsert
        ):
            db_pool.engine.lock_table(txn, "user_ips")

        for entry in to_update.items():
            (user_id, access_token, ip), (user_agent, device_id, last_seen) = entry

            db_pool.simple_upsert_txn(
                txn,
                table="user_ips",
                keyvalues={"user_id": user_id, "access_token": access_token, "ip": ip},
                values={
                    "user_agent": user_agent,
                    "device_id": device_id,
                    "last_seen": last_seen,
                },
                lock=False,
            )

            # Technically an access token might not be associated with
            # a device so we need to check.
            if device_id:
                # this is always an update rather than an upsert: the row should
                # already exist, and if it doesn't, that may be because it has been
                # deleted, and we don't want to re-create it.
                db_pool.simple_update_txn(
                    txn,
                    table="devices",
                    keyvalues={"user_id": user_id, "device_id": device_id},
                    updatevalues={
                        "user_agent": user_agent,
                        "last_seen": last_seen,
                        "ip": ip,
                    },
                )


class ReplicationStreamingClientIpStrategy(AbstractClientIpStrategy):
    """
    Strategy for writing client IPs by streaming them over replication to
    a designated writer worker.
    """

    def __init__(self, hs: "HomeServer"):
        self.hs = hs
        self._clock = hs.get_clock()

        self.client_ip_last_seen: LruCache[tuple, int] = LruCache(
            cache_name="client_ip_last_seen", max_size=50000
        )

    async def insert_client_ip(
        self, user_id: str, access_token: str, ip: str, user_agent: str, device_id: str
    ) -> None:
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

        self.hs.get_replication_command_handler().send_user_ip(
            user_id, access_token, ip, user_agent, device_id, now
        )
