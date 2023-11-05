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

from twisted.internet import defer

from synapse.replication.tcp.commands import PositionCommand

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

    def test_wait_for_stream_position(self) -> None:
        """Check that wait for stream position correctly waits for an update from the
        correct instance.
        """
        store = self.hs.get_datastores().main
        cmd_handler = self.hs.get_replication_command_handler()
        data_handler = self.hs.get_replication_data_handler()

        worker1 = self.make_worker_hs(
            "synapse.app.generic_worker",
            extra_config={
                "worker_name": "worker1",
                "run_background_tasks_on": "worker1",
                "redis": {"enabled": True},
            },
        )

        cache_id_gen = worker1.get_datastores().main._cache_id_gen
        assert cache_id_gen is not None

        self.replicate()

        # First, make sure the master knows that `worker1` exists.
        initial_token = cache_id_gen.get_current_token()
        cmd_handler.send_command(
            PositionCommand("caches", "worker1", initial_token, initial_token)
        )
        self.replicate()

        # Next send out a normal RDATA, and check that waiting for that stream
        # ID returns immediately.
        ctx = cache_id_gen.get_next()
        next_token = self.get_success(ctx.__aenter__())
        self.get_success(ctx.__aexit__(None, None, None))

        self.get_success(
            data_handler.wait_for_stream_position("worker1", "caches", next_token)
        )

        # `wait_for_stream_position` should only return once master receives a
        # notification that `next_token` has persisted.
        ctx_worker1 = cache_id_gen.get_next()
        next_token = self.get_success(ctx_worker1.__aenter__())

        d = defer.ensureDeferred(
            data_handler.wait_for_stream_position("worker1", "caches", next_token)
        )
        self.assertFalse(d.called)

        # ... updating the cache ID gen on the master still shouldn't cause the
        # deferred to wake up.
        assert store._cache_id_gen is not None
        ctx = store._cache_id_gen.get_next()
        self.get_success(ctx.__aenter__())
        self.get_success(ctx.__aexit__(None, None, None))

        d = defer.ensureDeferred(
            data_handler.wait_for_stream_position("worker1", "caches", next_token)
        )
        self.assertFalse(d.called)

        # ... but worker1 finishing (and so sending an update) should.
        self.get_success(ctx_worker1.__aexit__(None, None, None))

        self.assertTrue(d.called)

    def test_wait_for_stream_position_rdata(self) -> None:
        """Check that wait for stream position correctly waits for an update
        from the correct instance, when RDATA is sent.
        """
        store = self.hs.get_datastores().main
        cmd_handler = self.hs.get_replication_command_handler()
        data_handler = self.hs.get_replication_data_handler()

        worker1 = self.make_worker_hs(
            "synapse.app.generic_worker",
            extra_config={
                "worker_name": "worker1",
                "run_background_tasks_on": "worker1",
                "redis": {"enabled": True},
            },
        )

        cache_id_gen = worker1.get_datastores().main._cache_id_gen
        assert cache_id_gen is not None

        self.replicate()

        # First, make sure the master knows that `worker1` exists.
        initial_token = cache_id_gen.get_current_token()
        cmd_handler.send_command(
            PositionCommand("caches", "worker1", initial_token, initial_token)
        )
        self.replicate()

        # `wait_for_stream_position` should only return once master receives a
        # notification that `next_token2` has persisted.
        ctx_worker1 = cache_id_gen.get_next_mult(2)
        next_token1, next_token2 = self.get_success(ctx_worker1.__aenter__())

        d = defer.ensureDeferred(
            data_handler.wait_for_stream_position("worker1", "caches", next_token2)
        )
        self.assertFalse(d.called)

        # Insert an entry into the cache stream with token `next_token1`, but
        # not `next_token2`.
        self.get_success(
            store.db_pool.simple_insert(
                table="cache_invalidation_stream_by_instance",
                values={
                    "stream_id": next_token1,
                    "instance_name": "worker1",
                    "cache_func": "foo",
                    "keys": [],
                    "invalidation_ts": 0,
                },
            )
        )

        # Finish the context manager, triggering the data to be sent to master.
        self.get_success(ctx_worker1.__aexit__(None, None, None))

        # Master should get told about `next_token2`, so the deferred should
        # resolve.
        self.assertTrue(d.called)
