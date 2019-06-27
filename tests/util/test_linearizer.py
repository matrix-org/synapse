# -*- coding: utf-8 -*-
# Copyright 2016 OpenMarket Ltd
# Copyright 2018 New Vector Ltd
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

from six.moves import range

from twisted.internet import defer, reactor
from twisted.internet.defer import CancelledError

from synapse.util import Clock, logcontext
from synapse.util.async_helpers import Linearizer

from tests import unittest


class LinearizerTestCase(unittest.TestCase):
    @defer.inlineCallbacks
    def test_linearizer(self):
        linearizer = Linearizer()

        key = object()

        d1 = linearizer.queue(key)
        cm1 = yield d1

        d2 = linearizer.queue(key)
        self.assertFalse(d2.called)

        with cm1:
            self.assertFalse(d2.called)

        with (yield d2):
            pass

    def test_lots_of_queued_things(self):
        # we have one slow thing, and lots of fast things queued up behind it.
        # it should *not* explode the stack.
        linearizer = Linearizer()

        @defer.inlineCallbacks
        def func(i, sleep=False):
            with logcontext.LoggingContext("func(%s)" % i) as lc:
                with (yield linearizer.queue("")):
                    self.assertEqual(logcontext.LoggingContext.current_context(), lc)
                    if sleep:
                        yield Clock(reactor).sleep(0)

                self.assertEqual(logcontext.LoggingContext.current_context(), lc)

        func(0, sleep=True)
        for i in range(1, 100):
            func(i)

        return func(1000)

    @defer.inlineCallbacks
    def test_multiple_entries(self):
        limiter = Linearizer(max_count=3)

        key = object()

        d1 = limiter.queue(key)
        cm1 = yield d1

        d2 = limiter.queue(key)
        cm2 = yield d2

        d3 = limiter.queue(key)
        cm3 = yield d3

        d4 = limiter.queue(key)
        self.assertFalse(d4.called)

        d5 = limiter.queue(key)
        self.assertFalse(d5.called)

        with cm1:
            self.assertFalse(d4.called)
            self.assertFalse(d5.called)

        cm4 = yield d4
        self.assertFalse(d5.called)

        with cm3:
            self.assertFalse(d5.called)

        cm5 = yield d5

        with cm2:
            pass

        with cm4:
            pass

        with cm5:
            pass

        d6 = limiter.queue(key)
        with (yield d6):
            pass

    @defer.inlineCallbacks
    def test_cancellation(self):
        linearizer = Linearizer()

        key = object()

        d1 = linearizer.queue(key)
        cm1 = yield d1

        d2 = linearizer.queue(key)
        self.assertFalse(d2.called)

        d3 = linearizer.queue(key)
        self.assertFalse(d3.called)

        d2.cancel()

        with cm1:
            pass

        self.assertTrue(d2.called)
        try:
            yield d2
            self.fail("Expected d2 to raise CancelledError")
        except CancelledError:
            pass

        with (yield d3):
            pass
