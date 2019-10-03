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

from synapse.util.wheel_timer import WheelTimer

from .. import unittest


class WheelTimerTestCase(unittest.TestCase):
    def test_single_insert_fetch(self):
        wheel = WheelTimer(bucket_size=5)

        obj = object()
        wheel.insert(100, obj, 150)

        self.assertListEqual(wheel.fetch(101), [])
        self.assertListEqual(wheel.fetch(110), [])
        self.assertListEqual(wheel.fetch(120), [])
        self.assertListEqual(wheel.fetch(130), [])
        self.assertListEqual(wheel.fetch(149), [])
        self.assertListEqual(wheel.fetch(156), [obj])
        self.assertListEqual(wheel.fetch(170), [])

    def test_multi_insert(self):
        wheel = WheelTimer(bucket_size=5)

        obj1 = object()
        obj2 = object()
        obj3 = object()
        wheel.insert(100, obj1, 150)
        wheel.insert(105, obj2, 130)
        wheel.insert(106, obj3, 160)

        self.assertListEqual(wheel.fetch(110), [])
        self.assertListEqual(wheel.fetch(135), [obj2])
        self.assertListEqual(wheel.fetch(149), [])
        self.assertListEqual(wheel.fetch(158), [obj1])
        self.assertListEqual(wheel.fetch(160), [])
        self.assertListEqual(wheel.fetch(200), [obj3])
        self.assertListEqual(wheel.fetch(210), [])

    def test_insert_past(self):
        wheel = WheelTimer(bucket_size=5)

        obj = object()
        wheel.insert(100, obj, 50)
        self.assertListEqual(wheel.fetch(120), [obj])

    def test_insert_past_multi(self):
        wheel = WheelTimer(bucket_size=5)

        obj1 = object()
        obj2 = object()
        obj3 = object()
        wheel.insert(100, obj1, 150)
        wheel.insert(100, obj2, 140)
        wheel.insert(100, obj3, 50)
        self.assertListEqual(wheel.fetch(110), [obj3])
        self.assertListEqual(wheel.fetch(120), [])
        self.assertListEqual(wheel.fetch(147), [obj2])
        self.assertListEqual(wheel.fetch(200), [obj1])
        self.assertListEqual(wheel.fetch(240), [])
