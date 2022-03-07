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

from tests import unittest
from tests.utils import MockClock


class MockClockTestCase(unittest.TestCase):
    def setUp(self):
        self.clock = MockClock()

    def test_advance_time(self):
        start_time = self.clock.time()

        self.clock.advance_time(20)

        self.assertEqual(20, self.clock.time() - start_time)

    def test_later(self):
        invoked = [0, 0]

        def _cb0():
            invoked[0] = 1

        self.clock.call_later(10, _cb0)

        def _cb1():
            invoked[1] = 1

        self.clock.call_later(20, _cb1)

        self.assertFalse(invoked[0])

        self.clock.advance_time(15)

        self.assertTrue(invoked[0])
        self.assertFalse(invoked[1])

        self.clock.advance_time(5)

        self.assertTrue(invoked[1])

    def test_cancel_later(self):
        invoked = [0, 0]

        def _cb0():
            invoked[0] = 1

        t0 = self.clock.call_later(10, _cb0)

        def _cb1():
            invoked[1] = 1

        self.clock.call_later(20, _cb1)

        self.clock.cancel_call_later(t0)

        self.clock.advance_time(30)

        self.assertFalse(invoked[0])
        self.assertTrue(invoked[1])
