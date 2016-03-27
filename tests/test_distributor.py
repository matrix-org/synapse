# -*- coding: utf-8 -*-
# Copyright 2014-2016 OpenMarket Ltd
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

from . import unittest
from twisted.internet import defer

from mock import Mock, patch

from synapse.util.distributor import Distributor
from synapse.util.async import run_on_reactor


class DistributorTestCase(unittest.TestCase):

    def setUp(self):
        self.dist = Distributor()

    @defer.inlineCallbacks
    def test_signal_dispatch(self):
        self.dist.declare("alert")

        observer = Mock()
        self.dist.observe("alert", observer)

        d = self.dist.fire("alert", 1, 2, 3)
        yield d
        self.assertTrue(d.called)
        observer.assert_called_with(1, 2, 3)

    @defer.inlineCallbacks
    def test_signal_dispatch_deferred(self):
        self.dist.declare("whine")

        d_inner = defer.Deferred()

        def observer():
            return d_inner

        self.dist.observe("whine", observer)

        d_outer = self.dist.fire("whine")

        self.assertFalse(d_outer.called)

        d_inner.callback(None)
        yield d_outer
        self.assertTrue(d_outer.called)

    @defer.inlineCallbacks
    def test_signal_catch(self):
        self.dist.declare("alarm")

        observers = [Mock() for i in 1, 2]
        for o in observers:
            self.dist.observe("alarm", o)

        observers[0].side_effect = Exception("Awoogah!")

        with patch(
            "synapse.util.distributor.logger", spec=["warning"]
        ) as mock_logger:
            d = self.dist.fire("alarm", "Go")
            yield d
            self.assertTrue(d.called)

            observers[0].assert_called_once_with("Go")
            observers[1].assert_called_once_with("Go")

            self.assertEquals(mock_logger.warning.call_count, 1)
            self.assertIsInstance(
                mock_logger.warning.call_args[0][0], str
            )

    @defer.inlineCallbacks
    def test_signal_catch_no_suppress(self):
        # Gut-wrenching
        self.dist.suppress_failures = False

        self.dist.declare("whail")

        class MyException(Exception):
            pass

        @defer.inlineCallbacks
        def observer():
            yield run_on_reactor()
            raise MyException("Oopsie")

        self.dist.observe("whail", observer)

        d = self.dist.fire("whail")

        yield self.assertFailure(d, MyException)
        self.dist.suppress_failures = True

    @defer.inlineCallbacks
    def test_signal_prereg(self):
        observer = Mock()
        self.dist.observe("flare", observer)

        self.dist.declare("flare")
        yield self.dist.fire("flare", 4, 5)

        observer.assert_called_with(4, 5)

    def test_signal_undeclared(self):
        def code():
            self.dist.fire("notification")
        self.assertRaises(KeyError, code)
