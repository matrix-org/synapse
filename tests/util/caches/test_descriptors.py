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
import mock
from twisted.internet import defer
from synapse.util.caches import descriptors
from tests import unittest


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
