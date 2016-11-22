from synapse.rest.client.transactions import HttpTransactionCache
from synapse.rest.client.transactions import CLEANUP_PERIOD_MS
from twisted.internet import defer
from mock import Mock, call
from tests import unittest
from tests.utils import MockClock


class HttpTransactionCacheTestCase(unittest.TestCase):

    def setUp(self):
        self.clock = MockClock()
        self.cache = HttpTransactionCache(self.clock)

        self.mock_http_response = (200, "GOOD JOB!")
        self.mock_key = "foo"

    @defer.inlineCallbacks
    def test_executes_given_function(self):
        cb = Mock(
            return_value=defer.succeed(self.mock_http_response)
        )
        res = yield self.cache.fetch_or_execute(
            self.mock_key, cb, "some_arg", keyword="arg"
        )
        cb.assert_called_once_with("some_arg", keyword="arg")
        self.assertEqual(res, self.mock_http_response)

    @defer.inlineCallbacks
    def test_deduplicates_based_on_key(self):
        cb = Mock(
            return_value=defer.succeed(self.mock_http_response)
        )
        for i in range(3):  # invoke multiple times
            res = yield self.cache.fetch_or_execute(
                self.mock_key, cb, "some_arg", keyword="arg", changing_args=i
            )
            self.assertEqual(res, self.mock_http_response)
        # expect only a single call to do the work
        cb.assert_called_once_with("some_arg", keyword="arg", changing_args=0)

    @defer.inlineCallbacks
    def test_cleans_up(self):
        cb = Mock(
            return_value=defer.succeed(self.mock_http_response)
        )
        yield self.cache.fetch_or_execute(
            self.mock_key, cb, "an arg"
        )
        # should NOT have cleaned up yet
        self.clock.advance_time_msec(CLEANUP_PERIOD_MS / 2)

        yield self.cache.fetch_or_execute(
            self.mock_key, cb, "an arg"
        )
        # still using cache
        cb.assert_called_once_with("an arg")

        self.clock.advance_time_msec(CLEANUP_PERIOD_MS)

        yield self.cache.fetch_or_execute(
            self.mock_key, cb, "an arg"
        )
        # no longer using cache
        self.assertEqual(cb.call_count, 2)
        self.assertEqual(
            cb.call_args_list,
            [call("an arg",), call("an arg",)]
        )
