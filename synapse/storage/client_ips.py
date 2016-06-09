# -*- coding: utf-8 -*-
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

from ._base import SQLBaseStore, Cache

from twisted.internet import defer


# Number of msec of granularity to store the user IP 'last seen' time. Smaller
# times give more inserts into the database even for readonly API hits
# 120 seconds == 2 minutes
LAST_SEEN_GRANULARITY = 120 * 1000


class ClientIpStore(SQLBaseStore):

    def __init__(self, hs):
        self.client_ip_last_seen = Cache(
            name="client_ip_last_seen",
            keylen=4,
        )

        super(ClientIpStore, self).__init__(hs)

    @defer.inlineCallbacks
    def insert_client_ip(self, user, access_token, ip, user_agent):
        now = int(self._clock.time_msec())
        key = (user.to_string(), access_token, ip)

        try:
            last_seen = self.client_ip_last_seen.get(key)
        except KeyError:
            last_seen = None

        # Rate-limited inserts
        if last_seen is not None and (now - last_seen) < LAST_SEEN_GRANULARITY:
            defer.returnValue(None)

        self.client_ip_last_seen.prefill(key, now)

        # It's safe not to lock here: a) no unique constraint,
        # b) LAST_SEEN_GRANULARITY makes concurrent updates incredibly unlikely
        yield self._simple_upsert(
            "user_ips",
            keyvalues={
                "user_id": user.to_string(),
                "access_token": access_token,
                "ip": ip,
                "user_agent": user_agent,
            },
            values={
                "last_seen": now,
            },
            desc="insert_client_ip",
            lock=False,
        )
