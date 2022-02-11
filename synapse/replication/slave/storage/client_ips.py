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

from typing import TYPE_CHECKING

from synapse.storage.database import DatabasePool, LoggingDatabaseConnection
from synapse.storage.databases.main.client_ips import LAST_SEEN_GRANULARITY
from synapse.util.caches.lrucache import LruCache

from ._base import BaseSlavedStore

if TYPE_CHECKING:
    from synapse.server import HomeServer


class SlavedClientIpStore(BaseSlavedStore):
    def __init__(
        self,
        database: DatabasePool,
        db_conn: LoggingDatabaseConnection,
        hs: "HomeServer",
    ):
        super().__init__(database, db_conn, hs)

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

        self.hs.get_tcp_replication().send_user_ip(
            user_id, access_token, ip, user_agent, device_id, now
        )
