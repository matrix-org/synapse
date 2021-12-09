# Copyright 2021 The Matrix.org Foundation C.I.C.
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

# Use backported mock for AsyncMock support on Python 3.6.
from mock import Mock

from twisted.internet.defer import Deferred, ensureDeferred

from synapse.storage.background_updates import BackgroundUpdater

from tests import unittest
from tests.test_utils import make_awaitable


class BackgroundUpdateTestCase(unittest.HomeserverTestCase):
    def prepare(self, reactor, clock, homeserver):
        self.updates: BackgroundUpdater = self.hs.get_datastore().db_pool.updates
        # the base test class should have run the real bg updates for us
        self.assertTrue(
            self.get_success(self.updates.has_completed_background_updates())
        )

        self.update_handler = Mock()
        self.updates.register_background_update_handler(
            "test_update", self.update_handler
        )

    def test_do_background_update(self):
        # the time we claim it takes to update one item when running the update
        duration_ms = 10

        # the target runtime for each bg update
        target_background_update_duration_ms = 100

        store = self.hs.get_datastore()
        self.get_success(
            store.db_pool.simple_insert(
                "background_updates",
                values={"update_name": "test_update", "progress_json": '{"my_key": 1}'},
            )
        )

        # first step: make a bit of progress
        async def update(progress, count):
            await self.clock.sleep((count * duration_ms) / 1000)
            progress = {"my_key": progress["my_key"] + 1}
            await store.db_pool.runInteraction(
                "update_progress",
                self.updates._background_update_progress_txn,
                "test_update",
                progress,
            )
            return count

        self.update_handler.side_effect = update
        self.update_handler.reset_mock()
        res = self.get_success(
            self.updates.do_next_background_update(False),
            by=0.01,
        )
        self.assertFalse(res)

        # on the first call, we should get run with the default background update size
        self.update_handler.assert_called_once_with(
            {"my_key": 1}, self.updates.MINIMUM_BACKGROUND_BATCH_SIZE
        )

        # second step: complete the update
        # we should now get run with a much bigger number of items to update
        async def update(progress, count):
            self.assertEqual(progress, {"my_key": 2})
            self.assertAlmostEqual(
                count,
                target_background_update_duration_ms / duration_ms,
                places=0,
            )
            await self.updates._end_background_update("test_update")
            return count

        self.update_handler.side_effect = update
        self.update_handler.reset_mock()
        result = self.get_success(self.updates.do_next_background_update(False))
        self.assertFalse(result)
        self.update_handler.assert_called_once()

        # third step: we don't expect to be called any more
        self.update_handler.reset_mock()
        result = self.get_success(self.updates.do_next_background_update(False))
        self.assertTrue(result)
        self.assertFalse(self.update_handler.called)


class BackgroundUpdateControllerTestCase(unittest.HomeserverTestCase):
    def prepare(self, reactor, clock, homeserver):
        self.updates: BackgroundUpdater = self.hs.get_datastore().db_pool.updates
        # the base test class should have run the real bg updates for us
        self.assertTrue(
            self.get_success(self.updates.has_completed_background_updates())
        )

        self.update_deferred = Deferred()
        self.update_handler = Mock(return_value=self.update_deferred)
        self.updates.register_background_update_handler(
            "test_update", self.update_handler
        )

        # Mock out the AsyncContextManager
        self._update_ctx_manager = Mock(spec=["__aenter__", "__aexit__"])
        self._update_ctx_manager.__aenter__ = Mock(
            return_value=make_awaitable(None),
        )
        self._update_ctx_manager.__aexit__ = Mock(return_value=make_awaitable(None))

        # Mock out the `update_handler` callback
        self._on_update = Mock(return_value=self._update_ctx_manager)

        # Define a default batch size value that's not the same as the internal default
        # value (100).
        self._default_batch_size = 500

        # Register the callbacks with more mocks
        self.hs.get_module_api().register_background_update_controller_callbacks(
            on_update=self._on_update,
            min_batch_size=Mock(return_value=make_awaitable(self._default_batch_size)),
            default_batch_size=Mock(
                return_value=make_awaitable(self._default_batch_size),
            ),
        )

    def test_controller(self):
        store = self.hs.get_datastore()
        self.get_success(
            store.db_pool.simple_insert(
                "background_updates",
                values={"update_name": "test_update", "progress_json": "{}"},
            )
        )

        # Set the return value for the context manager.
        enter_defer = Deferred()
        self._update_ctx_manager.__aenter__ = Mock(return_value=enter_defer)

        # Start the background update.
        do_update_d = ensureDeferred(self.updates.do_next_background_update(True))

        self.pump()

        # `run_update` should have been called, but the update handler won't be
        # called until the `enter_defer` (returned by `__aenter__`) is resolved.
        self._on_update.assert_called_once_with(
            "test_update",
            "master",
            False,
        )
        self.assertFalse(do_update_d.called)
        self.assertFalse(self.update_deferred.called)

        # Resolving the `enter_defer` should call the update handler, which then
        # blocks.
        enter_defer.callback(100)
        self.pump()
        self.update_handler.assert_called_once_with({}, self._default_batch_size)
        self.assertFalse(self.update_deferred.called)
        self._update_ctx_manager.__aexit__.assert_not_called()

        # Resolving the update handler deferred should cause the
        # `do_next_background_update` to finish and return
        self.update_deferred.callback(100)
        self.pump()
        self._update_ctx_manager.__aexit__.assert_called()
        self.get_success(do_update_d)
