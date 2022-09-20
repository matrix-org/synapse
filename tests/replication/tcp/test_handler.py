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


class ChannelsTestCase(BaseMultiWorkerStreamTestCase):
    def test_subscribed_to_enough_redis_channels(self) -> None:
        # The default main process is subscribed to the USER_IP channel.
        self.assertCountEqual(
            self.hs.get_replication_command_handler()._channels_to_subscribe_to,
            ["USER_IP"],
        )

    def test_background_worker_subscribed_to_user_ip(self) -> None:
        # The default main process is subscribed to the USER_IP channel.
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

        # Advance so the Redis subscription gets processed
        self.pump(0.1)

        # The counts are 2 because both the main process and the worker are subscribed.
        self.assertEqual(len(self._redis_server._subscribers_by_channel[b"test"]), 2)
        self.assertEqual(
            len(self._redis_server._subscribers_by_channel[b"test/USER_IP"]), 2
        )

    def test_non_background_worker_not_subscribed_to_user_ip(self) -> None:
        # The default main process is subscribed to the USER_IP channel.
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

        # Advance so the Redis subscription gets processed
        self.pump(0.1)

        # The count is 2 because both the main process and the worker are subscribed.
        self.assertEqual(len(self._redis_server._subscribers_by_channel[b"test"]), 2)
        # For USER_IP, the count is 1 because only the main process is subscribed.
        self.assertEqual(
            len(self._redis_server._subscribers_by_channel[b"test/USER_IP"]), 1
        )
