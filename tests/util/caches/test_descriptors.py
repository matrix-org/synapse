# -*- coding: utf-8 -*-
# Copyright 2016 OpenMarket Ltd
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
import logging

import mock
from synapse.api.errors import SynapseError
from synapse.util import async
from synapse.util import logcontext
from twisted.internet import defer
from synapse.util.caches import descriptors
from tests import unittest

logger = logging.getLogger(__name__)


class DescriptorTestCase(unittest.TestCase):
    @defer.inlineCallbacks
    def test_cache(self):
        class Cls(object):
            def __init__(self):
                self.mock = mock.Mock()

            @descriptors.cached()
            def fn(self, arg1, arg2):
                return self.mock(arg1, arg2)

        obj = Cls()

        obj.mock.return_value = 'fish'
        r = yield obj.fn(1, 2)
        self.assertEqual(r, 'fish')
        obj.mock.assert_called_once_with(1, 2)
        obj.mock.reset_mock()

        # a call with different params should call the mock again
        obj.mock.return_value = 'chips'
        r = yield obj.fn(1, 3)
        self.assertEqual(r, 'chips')
        obj.mock.assert_called_once_with(1, 3)
        obj.mock.reset_mock()

        # the two values should now be cached
        r = yield obj.fn(1, 2)
        self.assertEqual(r, 'fish')
        r = yield obj.fn(1, 3)
        self.assertEqual(r, 'chips')
        obj.mock.assert_not_called()

    @defer.inlineCallbacks
    def test_cache_num_args(self):
        """Only the first num_args arguments should matter to the cache"""

        class Cls(object):
            def __init__(self):
                self.mock = mock.Mock()

            @descriptors.cached(num_args=1)
            def fn(self, arg1, arg2):
                return self.mock(arg1, arg2)

        obj = Cls()
        obj.mock.return_value = 'fish'
        r = yield obj.fn(1, 2)
        self.assertEqual(r, 'fish')
        obj.mock.assert_called_once_with(1, 2)
        obj.mock.reset_mock()

        # a call with different params should call the mock again
        obj.mock.return_value = 'chips'
        r = yield obj.fn(2, 3)
        self.assertEqual(r, 'chips')
        obj.mock.assert_called_once_with(2, 3)
        obj.mock.reset_mock()

        # the two values should now be cached; we should be able to vary
        # the second argument and still get the cached result.
        r = yield obj.fn(1, 4)
        self.assertEqual(r, 'fish')
        r = yield obj.fn(2, 5)
        self.assertEqual(r, 'chips')
        obj.mock.assert_not_called()

    def test_cache_logcontexts(self):
        """Check that logcontexts are set and restored correctly when
        using the cache."""

        complete_lookup = defer.Deferred()

        class Cls(object):
            @descriptors.cached()
            def fn(self, arg1):
                @defer.inlineCallbacks
                def inner_fn():
                    with logcontext.PreserveLoggingContext():
                        yield complete_lookup
                    defer.returnValue(1)

                return inner_fn()

        @defer.inlineCallbacks
        def do_lookup():
            with logcontext.LoggingContext() as c1:
                c1.name = "c1"
                r = yield obj.fn(1)
                self.assertEqual(logcontext.LoggingContext.current_context(),
                                 c1)
            defer.returnValue(r)

        def check_result(r):
            self.assertEqual(r, 1)

        obj = Cls()

        # set off a deferred which will do a cache lookup
        d1 = do_lookup()
        self.assertEqual(logcontext.LoggingContext.current_context(),
                         logcontext.LoggingContext.sentinel)
        d1.addCallback(check_result)

        # and another
        d2 = do_lookup()
        self.assertEqual(logcontext.LoggingContext.current_context(),
                         logcontext.LoggingContext.sentinel)
        d2.addCallback(check_result)

        # let the lookup complete
        complete_lookup.callback(None)

        return defer.gatherResults([d1, d2])

    def test_cache_logcontexts_with_exception(self):
        """Check that the cache sets and restores logcontexts correctly when
        the lookup function throws an exception"""

        class Cls(object):
            @descriptors.cached()
            def fn(self, arg1):
                @defer.inlineCallbacks
                def inner_fn():
                    yield async.run_on_reactor()
                    raise SynapseError(400, "blah")

                return inner_fn()

        @defer.inlineCallbacks
        def do_lookup():
            with logcontext.LoggingContext() as c1:
                c1.name = "c1"
                try:
                    yield obj.fn(1)
                    self.fail("No exception thrown")
                except SynapseError:
                    pass

                self.assertEqual(logcontext.LoggingContext.current_context(),
                                 c1)

        obj = Cls()

        # set off a deferred which will do a cache lookup
        d1 = do_lookup()
        self.assertEqual(logcontext.LoggingContext.current_context(),
                         logcontext.LoggingContext.sentinel)

        return d1

    @defer.inlineCallbacks
    def test_cache_default_args(self):
        class Cls(object):
            def __init__(self):
                self.mock = mock.Mock()

            @descriptors.cached()
            def fn(self, arg1, arg2=2, arg3=3):
                return self.mock(arg1, arg2, arg3)

        obj = Cls()

        obj.mock.return_value = 'fish'
        r = yield obj.fn(1, 2, 3)
        self.assertEqual(r, 'fish')
        obj.mock.assert_called_once_with(1, 2, 3)
        obj.mock.reset_mock()

        # a call with same params shouldn't call the mock again
        r = yield obj.fn(1, 2)
        self.assertEqual(r, 'fish')
        obj.mock.assert_not_called()
        obj.mock.reset_mock()

        # a call with different params should call the mock again
        obj.mock.return_value = 'chips'
        r = yield obj.fn(2, 3)
        self.assertEqual(r, 'chips')
        obj.mock.assert_called_once_with(2, 3, 3)
        obj.mock.reset_mock()

        # the two values should now be cached
        r = yield obj.fn(1, 2)
        self.assertEqual(r, 'fish')
        r = yield obj.fn(2, 3)
        self.assertEqual(r, 'chips')
        obj.mock.assert_not_called()
