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


from tests import unittest

from twisted.internet import defer

from synapse.util.async import Limiter


class LimiterTestCase(unittest.TestCase):

    @defer.inlineCallbacks
    def test_limiter(self):
        limiter = Limiter(3)

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

        self.assertTrue(d4.called)
        self.assertFalse(d5.called)

        with cm3:
            self.assertFalse(d5.called)

        self.assertTrue(d5.called)

        with cm2:
            pass

        with (yield d4):
            pass

        with (yield d5):
            pass

        d6 = limiter.queue(key)
        with (yield d6):
            pass
