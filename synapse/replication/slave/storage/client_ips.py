# -*- coding: utf-8 -*-
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

from synapse.storage.client_ips import LAST_SEEN_GRANULARITY
from synapse.util.caches import CACHE_SIZE_FACTOR
from synapse.util.caches.descriptors import Cache

from ._base import BaseSlavedStore


class SlavedClientIpStore(BaseSlavedStore):
    def __init__(self, db_conn, hs):
        super(SlavedClientIpStore, self).__init__(db_conn, hs)

        self.client_ip_last_seen = Cache(
            name="client_ip_last_seen",
            keylen=4,
            max_entries=50000 * CACHE_SIZE_FACTOR,
        )

    def insert_client_ip(self, user_id, access_token, ip, user_agent, device_id):
        now = int(self._clock.time_msec())
        key = (user_id, access_token, ip)

        try:
            last_seen = self.client_ip_last_seen.get(key)
        except KeyError:
            last_seen = None

        # Rate-limited inserts
        if last_seen is not None and (now - last_seen) < LAST_SEEN_GRANULARITY:
            return

        self.client_ip_last_seen.prefill(key, now)

        self.hs.get_tcp_replication().send_user_ip(
            user_id, access_token, ip, user_agent, device_id, now
        )
