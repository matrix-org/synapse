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


from tests import unittest
from twisted.internet import defer

from tests.utils import setup_test_homeserver


class RegistrationStoreTestCase(unittest.TestCase):

    @defer.inlineCallbacks
    def setUp(self):
        hs = yield setup_test_homeserver()
        self.db_pool = hs.get_db_pool()

        self.store = hs.get_datastore()

        self.user_id = "@my-user:test"
        self.tokens = [
            "AbCdEfGhIjKlMnOpQrStUvWxYz",
            "BcDeFgHiJkLmNoPqRsTuVwXyZa"
        ]
        self.pwhash = "{xx1}123456789"
        self.device_id = "akgjhdjklgshg"

    @defer.inlineCallbacks
    def test_register(self):
        yield self.store.register(self.user_id, self.tokens[0], self.pwhash)

        self.assertEquals(
            # TODO(paul): Surely this field should be 'user_id', not 'name'
            #  Additionally surely it shouldn't come in a 1-element list
            {"name": self.user_id, "password_hash": self.pwhash, "is_guest": 0},
            (yield self.store.get_user_by_id(self.user_id))
        )

        result = yield self.store.get_user_by_access_token(self.tokens[0])

        self.assertDictContainsSubset(
            {
                "name": self.user_id,
            },
            result
        )

        self.assertTrue("token_id" in result)

    @defer.inlineCallbacks
    def test_add_tokens(self):
        yield self.store.register(self.user_id, self.tokens[0], self.pwhash)
        yield self.store.add_access_token_to_user(self.user_id, self.tokens[1],
                                                  self.device_id)

        result = yield self.store.get_user_by_access_token(self.tokens[1])

        self.assertDictContainsSubset(
            {
                "name": self.user_id,
                "device_id": self.device_id,
            },
            result
        )

        self.assertTrue("token_id" in result)

    @defer.inlineCallbacks
    def test_user_delete_access_tokens(self):
        # add some tokens
        yield self.store.register(self.user_id, self.tokens[0], self.pwhash)
        yield self.store.add_access_token_to_user(self.user_id, self.tokens[1],
                                                  self.device_id)

        # now delete some
        yield self.store.user_delete_access_tokens(
            self.user_id, device_id=self.device_id, delete_refresh_tokens=True)

        # check they were deleted
        user = yield self.store.get_user_by_access_token(self.tokens[1])
        self.assertIsNone(user, "access token was not deleted by device_id")

        # check the one not associated with the device was not deleted
        user = yield self.store.get_user_by_access_token(self.tokens[0])
        self.assertEqual(self.user_id, user["name"])

        # now delete the rest
        yield self.store.user_delete_access_tokens(
            self.user_id, delete_refresh_tokens=True)

        user = yield self.store.get_user_by_access_token(self.tokens[0])
        self.assertIsNone(user,
                          "access token was not deleted without device_id")


class TokenGenerator:
    def __init__(self):
        self._last_issued_token = 0

    def generate(self, user_id):
        self._last_issued_token += 1
        return u"%s-%d" % (user_id, self._last_issued_token,)
