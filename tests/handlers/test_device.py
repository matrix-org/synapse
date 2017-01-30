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

import synapse.api.errors
import synapse.handlers.device

import synapse.storage
from synapse import types
from tests import unittest, utils

user1 = "@boris:aaa"
user2 = "@theresa:bbb"


class DeviceTestCase(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super(DeviceTestCase, self).__init__(*args, **kwargs)
        self.store = None    # type: synapse.storage.DataStore
        self.handler = None  # type: synapse.handlers.device.DeviceHandler
        self.clock = None    # type: utils.MockClock

    @defer.inlineCallbacks
    def setUp(self):
        hs = yield utils.setup_test_homeserver()
        self.handler = hs.get_device_handler()
        self.store = hs.get_datastore()
        self.clock = hs.get_clock()

    @defer.inlineCallbacks
    def test_device_is_created_if_doesnt_exist(self):
        res = yield self.handler.check_device_registered(
            user_id="@boris:foo",
            device_id="fco",
            initial_device_display_name="display name"
        )
        self.assertEqual(res, "fco")

        dev = yield self.handler.store.get_device("@boris:foo", "fco")
        self.assertEqual(dev["display_name"], "display name")

    @defer.inlineCallbacks
    def test_device_is_preserved_if_exists(self):
        res1 = yield self.handler.check_device_registered(
            user_id="@boris:foo",
            device_id="fco",
            initial_device_display_name="display name"
        )
        self.assertEqual(res1, "fco")

        res2 = yield self.handler.check_device_registered(
            user_id="@boris:foo",
            device_id="fco",
            initial_device_display_name="new display name"
        )
        self.assertEqual(res2, "fco")

        dev = yield self.handler.store.get_device("@boris:foo", "fco")
        self.assertEqual(dev["display_name"], "display name")

    @defer.inlineCallbacks
    def test_device_id_is_made_up_if_unspecified(self):
        device_id = yield self.handler.check_device_registered(
            user_id="@theresa:foo",
            device_id=None,
            initial_device_display_name="display"
        )

        dev = yield self.handler.store.get_device("@theresa:foo", device_id)
        self.assertEqual(dev["display_name"], "display")

    @defer.inlineCallbacks
    def test_get_devices_by_user(self):
        yield self._record_users()

        res = yield self.handler.get_devices_by_user(user1)
        self.assertEqual(3, len(res))
        device_map = {
            d["device_id"]: d for d in res
        }
        self.assertDictContainsSubset({
            "user_id": user1,
            "device_id": "xyz",
            "display_name": "display 0",
            "last_seen_ip": None,
            "last_seen_ts": None,
        }, device_map["xyz"])
        self.assertDictContainsSubset({
            "user_id": user1,
            "device_id": "fco",
            "display_name": "display 1",
            "last_seen_ip": "ip1",
            "last_seen_ts": 1000000,
        }, device_map["fco"])
        self.assertDictContainsSubset({
            "user_id": user1,
            "device_id": "abc",
            "display_name": "display 2",
            "last_seen_ip": "ip3",
            "last_seen_ts": 3000000,
        }, device_map["abc"])

    @defer.inlineCallbacks
    def test_get_device(self):
        yield self._record_users()

        res = yield self.handler.get_device(user1, "abc")
        self.assertDictContainsSubset({
            "user_id": user1,
            "device_id": "abc",
            "display_name": "display 2",
            "last_seen_ip": "ip3",
            "last_seen_ts": 3000000,
        }, res)

    @defer.inlineCallbacks
    def test_delete_device(self):
        yield self._record_users()

        # delete the device
        yield self.handler.delete_device(user1, "abc")

        # check the device was deleted
        with self.assertRaises(synapse.api.errors.NotFoundError):
            yield self.handler.get_device(user1, "abc")

        # we'd like to check the access token was invalidated, but that's a
        # bit of a PITA.

    @defer.inlineCallbacks
    def test_update_device(self):
        yield self._record_users()

        update = {"display_name": "new display"}
        yield self.handler.update_device(user1, "abc", update)

        res = yield self.handler.get_device(user1, "abc")
        self.assertEqual(res["display_name"], "new display")

    @defer.inlineCallbacks
    def test_update_unknown_device(self):
        update = {"display_name": "new_display"}
        with self.assertRaises(synapse.api.errors.NotFoundError):
            yield self.handler.update_device("user_id", "unknown_device_id",
                                             update)

    @defer.inlineCallbacks
    def _record_users(self):
        # check this works for both devices which have a recorded client_ip,
        # and those which don't.
        yield self._record_user(user1, "xyz", "display 0")
        yield self._record_user(user1, "fco", "display 1", "token1", "ip1")
        yield self._record_user(user1, "abc", "display 2", "token2", "ip2")
        yield self._record_user(user1, "abc", "display 2", "token3", "ip3")

        yield self._record_user(user2, "def", "dispkay", "token4", "ip4")

    @defer.inlineCallbacks
    def _record_user(self, user_id, device_id, display_name,
                     access_token=None, ip=None):
        device_id = yield self.handler.check_device_registered(
            user_id=user_id,
            device_id=device_id,
            initial_device_display_name=display_name
        )

        if ip is not None:
            yield self.store.insert_client_ip(
                types.UserID.from_string(user_id),
                access_token, ip, "user_agent", device_id)
            self.clock.advance_time(1000)
