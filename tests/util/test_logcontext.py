import twisted.python.failure
from twisted.internet import defer, reactor

from synapse.util import Clock, logcontext
from synapse.util.logcontext import LoggingContext

from .. import unittest


class LoggingContextTestCase(unittest.TestCase):
    def _check_test_key(self, value):
        self.assertEquals(LoggingContext.current_context().request, value)

    def test_with_context(self):
        with LoggingContext() as context_one:
            context_one.request = "test"
            self._check_test_key("test")

    @defer.inlineCallbacks
    def test_sleep(self):
        clock = Clock(reactor)

        @defer.inlineCallbacks
        def competing_callback():
            with LoggingContext() as competing_context:
                competing_context.request = "competing"
                yield clock.sleep(0)
                self._check_test_key("competing")

        reactor.callLater(0, competing_callback)

        with LoggingContext() as context_one:
            context_one.request = "one"
            yield clock.sleep(0)
            self._check_test_key("one")

    def _test_run_in_background(self, function):
        sentinel_context = LoggingContext.current_context()

        callback_completed = [False]

        def test():
            context_one.request = "one"
            d = function()

            def cb(res):
                self._check_test_key("one")
                callback_completed[0] = True
                return res

            d.addCallback(cb)

            return d

        with LoggingContext() as context_one:
            context_one.request = "one"

            # fire off function, but don't wait on it.
            logcontext.run_in_background(test)

            self._check_test_key("one")

        # now wait for the function under test to have run, and check that
        # the logcontext is left in a sane state.
        d2 = defer.Deferred()

        def check_logcontext():
            if not callback_completed[0]:
                reactor.callLater(0.01, check_logcontext)
                return

            # make sure that the context was reset before it got thrown back
            # into the reactor
            try:
                self.assertIs(LoggingContext.current_context(), sentinel_context)
                d2.callback(None)
            except BaseException:
                d2.errback(twisted.python.failure.Failure())

        reactor.callLater(0.01, check_logcontext)

        # test is done once d2 finishes
        return d2

    def test_run_in_background_with_blocking_fn(self):
        @defer.inlineCallbacks
        def blocking_function():
            yield Clock(reactor).sleep(0)

        return self._test_run_in_background(blocking_function)

    def test_run_in_background_with_non_blocking_fn(self):
        @defer.inlineCallbacks
        def nonblocking_function():
            with logcontext.PreserveLoggingContext():
                yield defer.succeed(None)

        return self._test_run_in_background(nonblocking_function)

    def test_run_in_background_with_chained_deferred(self):
        # a function which returns a deferred which looks like it has been
        # called, but is actually paused
        def testfunc():
            return logcontext.make_deferred_yieldable(_chained_deferred_function())

        return self._test_run_in_background(testfunc)

    @defer.inlineCallbacks
    def test_make_deferred_yieldable(self):
        # a function which retuns an incomplete deferred, but doesn't follow
        # the synapse rules.
        def blocking_function():
            d = defer.Deferred()
            reactor.callLater(0, d.callback, None)
            return d

        sentinel_context = LoggingContext.current_context()

        with LoggingContext() as context_one:
            context_one.request = "one"

            d1 = logcontext.make_deferred_yieldable(blocking_function())
            # make sure that the context was reset by make_deferred_yieldable
            self.assertIs(LoggingContext.current_context(), sentinel_context)

            yield d1

            # now it should be restored
            self._check_test_key("one")

    @defer.inlineCallbacks
    def test_make_deferred_yieldable_with_chained_deferreds(self):
        sentinel_context = LoggingContext.current_context()

        with LoggingContext() as context_one:
            context_one.request = "one"

            d1 = logcontext.make_deferred_yieldable(_chained_deferred_function())
            # make sure that the context was reset by make_deferred_yieldable
            self.assertIs(LoggingContext.current_context(), sentinel_context)

            yield d1

            # now it should be restored
            self._check_test_key("one")

    @defer.inlineCallbacks
    def test_make_deferred_yieldable_on_non_deferred(self):
        """Check that make_deferred_yieldable does the right thing when its
        argument isn't actually a deferred"""

        with LoggingContext() as context_one:
            context_one.request = "one"

            d1 = logcontext.make_deferred_yieldable("bum")
            self._check_test_key("one")

            r = yield d1
            self.assertEqual(r, "bum")
            self._check_test_key("one")


# a function which returns a deferred which has been "called", but
# which had a function which returned another incomplete deferred on
# its callback list, so won't yet call any other new callbacks.
def _chained_deferred_function():
    d = defer.succeed(None)

    def cb(res):
        d2 = defer.Deferred()
        reactor.callLater(0, d2.callback, res)
        return d2

    d.addCallback(cb)
    return d
