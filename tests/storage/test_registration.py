# -*- coding: utf-8 -*-
# Copyright 2014 OpenMarket Ltd
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

from synapse.storage.registration import RegistrationStore

from tests.utils import setup_test_homeserver


class RegistrationStoreTestCase(unittest.TestCase):

    @defer.inlineCallbacks
    def setUp(self):
        hs = yield setup_test_homeserver()

        self.store = RegistrationStore(hs)

        self.user_id = "@my-user:test"
        self.tokens = ["AbCdEfGhIjKlMnOpQrStUvWxYz",
                        "BcDeFgHiJkLmNoPqRsTuVwXyZa"]
        self.pwhash = "{xx1}123456789"

    @defer.inlineCallbacks
    def test_register(self):
        yield self.store.register(self.user_id, self.tokens[0], self.pwhash)

        self.assertEquals(
            # TODO(paul): Surely this field should be 'user_id', not 'name'
            #  Additionally surely it shouldn't come in a 1-element list
            [{"name": self.user_id, "password_hash": self.pwhash}],
            (yield self.store.get_user_by_id(self.user_id))
        )

        self.assertEquals(
            {"admin": 0,
             "device_id": None,
             "name": self.user_id,
             "token_id": 1},
            (yield self.store.get_user_by_token(self.tokens[0]))
        )

    @defer.inlineCallbacks
    def test_add_tokens(self):
        yield self.store.register(self.user_id, self.tokens[0], self.pwhash)
        yield self.store.add_access_token_to_user(self.user_id, self.tokens[1])

        self.assertEquals(
            {"admin": 0,
             "device_id": None,
             "name": self.user_id,
             "token_id": 2},
            (yield self.store.get_user_by_token(self.tokens[1]))
        )

