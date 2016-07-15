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

from twisted.internet import defer

from synapse.handlers.device import DeviceHandler
from tests import unittest
from tests.utils import setup_test_homeserver


class DeviceHandlers(object):
    def __init__(self, hs):
        self.device_handler = DeviceHandler(hs)


class DeviceTestCase(unittest.TestCase):
    @defer.inlineCallbacks
    def setUp(self):
        self.hs = yield setup_test_homeserver(handlers=None)
        self.hs.handlers = handlers = DeviceHandlers(self.hs)
        self.handler = handlers.device_handler

    @defer.inlineCallbacks
    def test_device_is_created_if_doesnt_exist(self):
        res = yield self.handler.check_device_registered(
            user_id="boris",
            device_id="fco",
            initial_device_display_name="display name"
        )
        self.assertEqual(res, "fco")

        dev = yield self.handler.store.get_device("boris", "fco")
        self.assertEqual(dev["display_name"], "display name")

    @defer.inlineCallbacks
    def test_device_is_preserved_if_exists(self):
        res1 = yield self.handler.check_device_registered(
            user_id="boris",
            device_id="fco",
            initial_device_display_name="display name"
        )
        self.assertEqual(res1, "fco")

        res2 = yield self.handler.check_device_registered(
            user_id="boris",
            device_id="fco",
            initial_device_display_name="new display name"
        )
        self.assertEqual(res2, "fco")

        dev = yield self.handler.store.get_device("boris", "fco")
        self.assertEqual(dev["display_name"], "display name")

    @defer.inlineCallbacks
    def test_device_id_is_made_up_if_unspecified(self):
        device_id = yield self.handler.check_device_registered(
            user_id="theresa",
            device_id=None,
            initial_device_display_name="display"
        )

        dev = yield self.handler.store.get_device("theresa", device_id)
        self.assertEqual(dev["display_name"], "display")
