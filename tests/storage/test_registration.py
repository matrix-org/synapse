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


from twisted.internet import defer

from synapse.api.constants import UserTypes

from tests import unittest
from tests.utils import setup_test_homeserver


class RegistrationStoreTestCase(unittest.TestCase):
    @defer.inlineCallbacks
    def setUp(self):
        hs = yield setup_test_homeserver(self.addCleanup)

        self.store = hs.get_datastore()

        self.user_id = "@my-user:test"
        self.tokens = ["AbCdEfGhIjKlMnOpQrStUvWxYz", "BcDeFgHiJkLmNoPqRsTuVwXyZa"]
        self.pwhash = "{xx1}123456789"
        self.device_id = "akgjhdjklgshg"

    @defer.inlineCallbacks
    def test_register(self):
        yield self.store.register_user(self.user_id, self.pwhash)

        self.assertEquals(
            {
                # TODO(paul): Surely this field should be 'user_id', not 'name'
                "name": self.user_id,
                "password_hash": self.pwhash,
                "admin": 0,
                "is_guest": 0,
                "consent_version": None,
                "consent_server_notice_sent": None,
                "appservice_id": None,
                "creation_ts": 1000,
                "user_type": None,
                "deactivated": 0,
            },
            (yield self.store.get_user_by_id(self.user_id)),
        )

    @defer.inlineCallbacks
    def test_add_tokens(self):
        yield self.store.register_user(self.user_id, self.pwhash)
        yield self.store.add_access_token_to_user(
            self.user_id, self.tokens[1], self.device_id, valid_until_ms=None
        )

        result = yield self.store.get_user_by_access_token(self.tokens[1])

        self.assertDictContainsSubset(
            {"name": self.user_id, "device_id": self.device_id}, result
        )

        self.assertTrue("token_id" in result)

    @defer.inlineCallbacks
    def test_user_delete_access_tokens(self):
        # add some tokens
        yield self.store.register_user(self.user_id, self.pwhash)
        yield self.store.add_access_token_to_user(
            self.user_id, self.tokens[0], device_id=None, valid_until_ms=None
        )
        yield self.store.add_access_token_to_user(
            self.user_id, self.tokens[1], self.device_id, valid_until_ms=None
        )

        # now delete some
        yield self.store.user_delete_access_tokens(
            self.user_id, device_id=self.device_id
        )

        # check they were deleted
        user = yield self.store.get_user_by_access_token(self.tokens[1])
        self.assertIsNone(user, "access token was not deleted by device_id")

        # check the one not associated with the device was not deleted
        user = yield self.store.get_user_by_access_token(self.tokens[0])
        self.assertEqual(self.user_id, user["name"])

        # now delete the rest
        yield self.store.user_delete_access_tokens(self.user_id)

        user = yield self.store.get_user_by_access_token(self.tokens[0])
        self.assertIsNone(user, "access token was not deleted without device_id")

    @defer.inlineCallbacks
    def test_is_support_user(self):
        TEST_USER = "@test:test"
        SUPPORT_USER = "@support:test"

        res = yield self.store.is_support_user(None)
        self.assertFalse(res)
        yield self.store.register_user(user_id=TEST_USER, password_hash=None)
        res = yield self.store.is_support_user(TEST_USER)
        self.assertFalse(res)

        yield self.store.register_user(
            user_id=SUPPORT_USER, password_hash=None, user_type=UserTypes.SUPPORT
        )
        res = yield self.store.is_support_user(SUPPORT_USER)
        self.assertTrue(res)
