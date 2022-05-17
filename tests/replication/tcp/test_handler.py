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

from tests.replication._base import BaseMultiWorkerStreamTestCase
from tests.unittest import HomeserverTestCase, override_config

try:
    import hiredis
except ImportError:
    hiredis = None  # type: ignore


class ChannelsMainTestCase(HomeserverTestCase):
    if not hiredis:
        skip = "Requires hiredis"

    @override_config({"redis": {"enabled": True}})
    def test_subscribed_to_enough_redis_channels(self) -> None:
        # The default main process is subscribed to USER_IP and all RDATA channels.
        self.assertCountEqual(
            self.hs.get_replication_command_handler()._channels_to_subscribe_to,
            ["USER_IP"],
        )


class ChannelsWorkerTestCase(BaseMultiWorkerStreamTestCase):
    if not hiredis:
        skip = "Requires hiredis"

    def test_background_worker_subscribed_to_user_ip(self) -> None:
        # The default main process is subscribed to USER_IP and all RDATA channels.
        worker1 = self.make_worker_hs(
            "synapse.app.generic_worker",
            extra_config={
                "worker_name": "worker1",
                "run_background_tasks_on": "worker1",
                "redis": {"enabled": True},
            },
        )
        self.assertIn(
            "USER_IP",
            worker1.get_replication_command_handler()._channels_to_subscribe_to,
        )

    def test_non_background_worker_not_subscribed_to_user_ip(self) -> None:
        # The default main process is subscribed to USER_IP and all RDATA channels.
        worker2 = self.make_worker_hs(
            "synapse.app.generic_worker",
            extra_config={
                "worker_name": "worker2",
                "run_background_tasks_on": "worker1",
                "redis": {"enabled": True},
            },
        )
        self.assertNotIn(
            "USER_IP",
            worker2.get_replication_command_handler()._channels_to_subscribe_to,
        )
