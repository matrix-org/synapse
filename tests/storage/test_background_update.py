from tests import unittest
from twisted.internet import defer

from tests.utils import setup_test_homeserver

from mock import Mock


class BackgroundUpdateTestCase(unittest.TestCase):

    @defer.inlineCallbacks
    def setUp(self):
        hs = yield setup_test_homeserver()  # type: synapse.server.HomeServer
        self.store = hs.get_datastore()
        self.clock = hs.get_clock()

        self.update_handler = Mock()

        yield self.store.register_background_update_handler(
            "test_update", self.update_handler
        )

        # run the real background updates, to get them out the way
        # (perhaps we should run them as part of the test HS setup, since we
        # run all of the other schema setup stuff there?)
        while True:
            res = yield self.store.do_next_background_update(1000)
            if res is None:
                break

    @defer.inlineCallbacks
    def test_do_background_update(self):
        desired_count = 1000
        duration_ms = 42

        # first step: make a bit of progress
        @defer.inlineCallbacks
        def update(progress, count):
            self.clock.advance_time_msec(count * duration_ms)
            progress = {"my_key": progress["my_key"] + 1}
            yield self.store.runInteraction(
                "update_progress",
                self.store._background_update_progress_txn,
                "test_update",
                progress,
            )
            defer.returnValue(count)

        self.update_handler.side_effect = update

        yield self.store.start_background_update("test_update", {"my_key": 1})

        self.update_handler.reset_mock()
        result = yield self.store.do_next_background_update(
            duration_ms * desired_count
        )
        self.assertIsNotNone(result)
        self.update_handler.assert_called_once_with(
            {"my_key": 1}, self.store.DEFAULT_BACKGROUND_BATCH_SIZE
        )

        # second step: complete the update
        @defer.inlineCallbacks
        def update(progress, count):
            yield self.store._end_background_update("test_update")
            defer.returnValue(count)

        self.update_handler.side_effect = update
        self.update_handler.reset_mock()
        result = yield self.store.do_next_background_update(
            duration_ms * desired_count
        )
        self.assertIsNotNone(result)
        self.update_handler.assert_called_once_with(
            {"my_key": 2}, desired_count
        )

        # third step: we don't expect to be called any more
        self.update_handler.reset_mock()
        result = yield self.store.do_next_background_update(
            duration_ms * desired_count
        )
        self.assertIsNone(result)
        self.assertFalse(self.update_handler.called)
