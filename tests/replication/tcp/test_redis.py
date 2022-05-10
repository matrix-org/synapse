# Copyright 2022 The Matrix.org Foundation C.I.C.
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

try:
    # We only import it to see if it's installed, so ignore the 'unused' import
    import txredisapi  # noqa: F401

    HAVE_TXREDISAPI = True
except ImportError:
    HAVE_TXREDISAPI = False

from tests.replication._base import BaseMultiWorkerStreamTestCase
from tests.unittest import HomeserverTestCase

ALL_RDATA_CHANNELS = [
    "RDATA/account_data",
    "RDATA/backfill",
    "RDATA/caches",
    "RDATA/device_lists",
    "RDATA/events",
    "RDATA/federation",
    "RDATA/groups",
    "RDATA/presence",
    "RDATA/presence_federation",
    "RDATA/push_rules",
    "RDATA/pushers",
    "RDATA/receipts",
    "RDATA/tag_account_data",
    "RDATA/to_device",
    "RDATA/typing",
    "RDATA/user_signature",
]


class RedisTestCase(HomeserverTestCase):
    if not HAVE_TXREDISAPI:
        skip = "Redis extras not installed"

    def test_subscribed_to_enough_redis_channels(self) -> None:
        from synapse.replication.tcp.redis import RedisDirectTcpReplicationClientFactory

        # The default main process is subscribed to USER_IP and all RDATA channels.
        self.assertCountEqual(
            RedisDirectTcpReplicationClientFactory.channels_to_subscribe_to_for_config(
                self.hs.config
            ),
            [
                "USER_IP",
            ]
            + ALL_RDATA_CHANNELS,
        )


class RedisWorkerTestCase(BaseMultiWorkerStreamTestCase):
    if not HAVE_TXREDISAPI:
        skip = "Redis extras not installed"

    def test_background_worker_subscribed_to_user_ip(self) -> None:
        from synapse.replication.tcp.redis import RedisDirectTcpReplicationClientFactory

        # The default main process is subscribed to USER_IP and all RDATA channels.
        worker1 = self.make_worker_hs(
            "synapse.app.generic_worker",
            extra_config={
                "worker_name": "worker1",
                "run_background_tasks_on": "worker1",
            },
        )
        self.assertIn(
            "USER_IP",
            RedisDirectTcpReplicationClientFactory.channels_to_subscribe_to_for_config(
                worker1.config
            ),
        )

    def test_non_background_worker_not_subscribed_to_user_ip(self) -> None:
        from synapse.replication.tcp.redis import RedisDirectTcpReplicationClientFactory

        # The default main process is subscribed to USER_IP and all RDATA channels.
        worker2 = self.make_worker_hs(
            "synapse.app.generic_worker",
            extra_config={
                "worker_name": "worker2",
                "run_background_tasks_on": "worker1",
            },
        )
        self.assertNotIn(
            "USER_IP",
            RedisDirectTcpReplicationClientFactory.channels_to_subscribe_to_for_config(
                worker2.config
            ),
        )
