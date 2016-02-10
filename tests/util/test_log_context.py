from twisted.internet import defer
from twisted.internet import reactor
from .. import unittest

from synapse.util.async import sleep
from synapse.util.logcontext import LoggingContext


class LoggingContextTestCase(unittest.TestCase):

    def _check_test_key(self, value):
        self.assertEquals(
            LoggingContext.current_context().test_key, value
        )

    def test_with_context(self):
        with LoggingContext() as context_one:
            context_one.test_key = "test"
            self._check_test_key("test")

    @defer.inlineCallbacks
    def test_sleep(self):
        @defer.inlineCallbacks
        def competing_callback():
            with LoggingContext() as competing_context:
                competing_context.test_key = "competing"
                yield sleep(0)
                self._check_test_key("competing")

        reactor.callLater(0, competing_callback)

        with LoggingContext() as context_one:
            context_one.test_key = "one"
            yield sleep(0)
            self._check_test_key("one")
