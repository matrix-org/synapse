# -*- coding: utf-8 -*-
# Copyright 2015 OpenMarket Ltd
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

import pymacaroons

from mock import Mock, NonCallableMock
from synapse.handlers.register import RegistrationHandler
from tests import unittest
from tests.utils import setup_test_homeserver
from twisted.internet import defer


class RegisterHandlers(object):
    def __init__(self, hs):
        self.registration_handler = RegistrationHandler(hs)


class RegisterTestCase(unittest.TestCase):
    @defer.inlineCallbacks
    def setUp(self):
        self.hs = yield setup_test_homeserver(handlers=None)
        self.hs.handlers = RegisterHandlers(self.hs)

    def test_token_is_a_macaroon(self):
        self.hs.config.macaroon_secret_key = "this key is a huge secret"

        token = self.hs.handlers.registration_handler.generate_token("some_user")
        # Check that we can parse the thing with pymacaroons
        macaroon = pymacaroons.Macaroon.deserialize(token)
        # The most basic of sanity checks
        if "some_user" not in macaroon.inspect():
            self.fail("some_user was not in %s" % macaroon.inspect())

    def test_macaroon_caveats(self):
        self.hs.config.macaroon_secret_key = "this key is a massive secret"
        self.hs.clock.now = 5000

        token = self.hs.handlers.registration_handler.generate_token("a_user")
        macaroon = pymacaroons.Macaroon.deserialize(token)

        def verify_gen(caveat):
            return caveat == "gen = 1"

        def verify_user(caveat):
            return caveat == "user_id = a_user"

        def verify_type(caveat):
            return caveat == "type = access"

        def verify_expiry(caveat):
            return caveat == "time < 8600000"

        v = pymacaroons.Verifier()
        v.satisfy_general(verify_gen)
        v.satisfy_general(verify_user)
        v.satisfy_general(verify_type)
        v.satisfy_general(verify_expiry)
        v.verify(macaroon, self.hs.config.macaroon_secret_key)
