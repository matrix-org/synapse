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

import logging

from twisted.internet import defer, reactor

from ._base import Cache
from . import background_updates

import os

logger = logging.getLogger(__name__)

# Number of msec of granularity to store the user IP 'last seen' time. Smaller
# times give more inserts into the database even for readonly API hits
# 120 seconds == 2 minutes
LAST_SEEN_GRANULARITY = 120 * 1000


CACHE_SIZE_FACTOR = float(os.environ.get("SYNAPSE_CACHE_FACTOR", 0.1))


class ClientIpStore(background_updates.BackgroundUpdateStore):
    def __init__(self, hs):
        self.client_ip_last_seen = Cache(
            name="client_ip_last_seen",
            keylen=4,
            max_entries=50000 * CACHE_SIZE_FACTOR,
        )

        super(ClientIpStore, self).__init__(hs)

        self.register_background_index_update(
            "user_ips_device_index",
            index_name="user_ips_device_id",
            table="user_ips",
            columns=["user_id", "device_id", "last_seen"],
        )

        self._batch_row_update = {}

        self._client_ip_looper = self._clock.looping_call(
            self._update_client_ips_batch, 5 * 1000
        )
        reactor.addSystemEventTrigger("before", "shutdown", self._update_client_ips_batch)

    def insert_client_ip(self, user, access_token, ip, user_agent, device_id):
        now = int(self._clock.time_msec())
        key = (user.to_string(), access_token, ip)

        try:
            last_seen = self.client_ip_last_seen.get(key)
        except KeyError:
            last_seen = None

        # Rate-limited inserts
        if last_seen is not None and (now - last_seen) < LAST_SEEN_GRANULARITY:
            return

        self.client_ip_last_seen.prefill(key, now)

        self._batch_row_update[key] = (user_agent, device_id, now)

    def _update_client_ips_batch(self):
        to_update = self._batch_row_update
        self._batch_row_update = {}
        return self.runInteraction(
            "_update_client_ips_batch", self._update_client_ips_batch_txn, to_update
        )

    def _update_client_ips_batch_txn(self, txn, to_update):
        self.database_engine.lock_table(txn, "user_ips")

        for entry in to_update.iteritems():
            (user_id, access_token, ip), (user_agent, device_id, last_seen) = entry

            self._simple_upsert_txn(
                txn,
                table="user_ips",
                keyvalues={
                    "user_id": user_id,
                    "access_token": access_token,
                    "ip": ip,
                    "user_agent": user_agent,
                    "device_id": device_id,
                },
                values={
                    "last_seen": last_seen,
                },
                lock=False,
            )

    @defer.inlineCallbacks
    def get_last_client_ip_by_device(self, devices):
        """For each device_id listed, give the user_ip it was last seen on

        Args:
            devices (iterable[(str, str)]):  list of (user_id, device_id) pairs

        Returns:
            defer.Deferred: resolves to a dict, where the keys
            are (user_id, device_id) tuples. The values are also dicts, with
            keys giving the column names
        """

        res = yield self.runInteraction(
            "get_last_client_ip_by_device",
            self._get_last_client_ip_by_device_txn,
            retcols=(
                "user_id",
                "access_token",
                "ip",
                "user_agent",
                "device_id",
                "last_seen",
            ),
            devices=devices
        )

        ret = {(d["user_id"], d["device_id"]): d for d in res}
        defer.returnValue(ret)

    @classmethod
    def _get_last_client_ip_by_device_txn(cls, txn, devices, retcols):
        where_clauses = []
        bindings = []
        for (user_id, device_id) in devices:
            if device_id is None:
                where_clauses.append("(user_id = ? AND device_id IS NULL)")
                bindings.extend((user_id, ))
            else:
                where_clauses.append("(user_id = ? AND device_id = ?)")
                bindings.extend((user_id, device_id))

        if not where_clauses:
            return []

        inner_select = (
            "SELECT MAX(last_seen) mls, user_id, device_id FROM user_ips "
            "WHERE %(where)s "
            "GROUP BY user_id, device_id"
        ) % {
            "where": " OR ".join(where_clauses),
        }

        sql = (
            "SELECT %(retcols)s FROM user_ips "
            "JOIN (%(inner_select)s) ips ON"
            "    user_ips.last_seen = ips.mls AND"
            "    user_ips.user_id = ips.user_id AND"
            "    (user_ips.device_id = ips.device_id OR"
            "         (user_ips.device_id IS NULL AND ips.device_id IS NULL)"
            "    )"
        ) % {
            "retcols": ",".join("user_ips." + c for c in retcols),
            "inner_select": inner_select,
        }

        txn.execute(sql, bindings)
        return cls.cursor_to_dict(txn)
