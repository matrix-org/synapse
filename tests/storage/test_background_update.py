from unittest.mock import Mock

from synapse.storage.background_updates import BackgroundUpdater

from tests import unittest


class BackgroundUpdateTestCase(unittest.HomeserverTestCase):
    def prepare(self, reactor, clock, homeserver):
        self.updates = (
            self.hs.get_datastore().db_pool.updates
        )  # type: BackgroundUpdater
        # the base test class should have run the real bg updates for us
        self.assertTrue(
            self.get_success(self.updates.has_completed_background_updates())
        )

        self.update_handler = Mock()
        self.updates.register_background_update_handler(
            "test_update", self.update_handler
        )

    def test_do_background_update(self):
        # the time we claim each update takes
        duration_ms = 42

        # the target runtime for each bg update
        target_background_update_duration_ms = 50000

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
            self.updates.do_next_background_update(
                target_background_update_duration_ms
            ),
            by=0.1,
        )
        self.assertFalse(res)

        # on the first call, we should get run with the default background update size
        self.update_handler.assert_called_once_with(
            {"my_key": 1}, self.updates.DEFAULT_BACKGROUND_BATCH_SIZE
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
        result = self.get_success(
            self.updates.do_next_background_update(target_background_update_duration_ms)
        )
        self.assertFalse(result)
        self.update_handler.assert_called_once()

        # third step: we don't expect to be called any more
        self.update_handler.reset_mock()
        result = self.get_success(
            self.updates.do_next_background_update(target_background_update_duration_ms)
        )
        self.assertTrue(result)
        self.assertFalse(self.update_handler.called)
