# -*- coding: utf-8 -*-
# Copyright 2015, 2016 OpenMarket Ltd
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
from mock import Mock

import pymacaroons

from twisted.internet import defer

import synapse
import synapse.api.errors
from synapse.api.errors import ResourceLimitError
from synapse.handlers.auth import AuthHandler

from tests import unittest
from tests.utils import setup_test_homeserver


class AuthHandlers(object):
    def __init__(self, hs):
        self.auth_handler = AuthHandler(hs)


class AuthTestCase(unittest.TestCase):
    @defer.inlineCallbacks
    def setUp(self):
        self.hs = yield setup_test_homeserver(self.addCleanup, handlers=None)
        self.hs.handlers = AuthHandlers(self.hs)
        self.auth_handler = self.hs.handlers.auth_handler
        self.macaroon_generator = self.hs.get_macaroon_generator()

        # MAU tests
        # AuthBlocking reads from the hs' config on initialization. We need to
        # modify its config instead of the hs'
        self.auth_blocking = self.hs.get_auth()._auth_blocking
        self.auth_blocking._max_mau_value = 50

        self.small_number_of_users = 1
        self.large_number_of_users = 100

    def test_token_is_a_macaroon(self):
        token = self.macaroon_generator.generate_access_token("some_user")
        # Check that we can parse the thing with pymacaroons
        macaroon = pymacaroons.Macaroon.deserialize(token)
        # The most basic of sanity checks
        if "some_user" not in macaroon.inspect():
            self.fail("some_user was not in %s" % macaroon.inspect())

    def test_macaroon_caveats(self):
        self.hs.clock.now = 5000

        token = self.macaroon_generator.generate_access_token("a_user")
        macaroon = pymacaroons.Macaroon.deserialize(token)

        def verify_gen(caveat):
            return caveat == "gen = 1"

        def verify_user(caveat):
            return caveat == "user_id = a_user"

        def verify_type(caveat):
            return caveat == "type = access"

        def verify_nonce(caveat):
            return caveat.startswith("nonce =")

        v = pymacaroons.Verifier()
        v.satisfy_general(verify_gen)
        v.satisfy_general(verify_user)
        v.satisfy_general(verify_type)
        v.satisfy_general(verify_nonce)
        v.verify(macaroon, self.hs.config.macaroon_secret_key)

    @defer.inlineCallbacks
    def test_short_term_login_token_gives_user_id(self):
        self.hs.clock.now = 1000

        token = self.macaroon_generator.generate_short_term_login_token("a_user", 5000)
        user_id = yield defer.ensureDeferred(
            self.auth_handler.validate_short_term_login_token_and_get_user_id(token)
        )
        self.assertEqual("a_user", user_id)

        # when we advance the clock, the token should be rejected
        self.hs.clock.now = 6000
        with self.assertRaises(synapse.api.errors.AuthError):
            yield defer.ensureDeferred(
                self.auth_handler.validate_short_term_login_token_and_get_user_id(token)
            )

    @defer.inlineCallbacks
    def test_short_term_login_token_cannot_replace_user_id(self):
        token = self.macaroon_generator.generate_short_term_login_token("a_user", 5000)
        macaroon = pymacaroons.Macaroon.deserialize(token)

        user_id = yield defer.ensureDeferred(
            self.auth_handler.validate_short_term_login_token_and_get_user_id(
                macaroon.serialize()
            )
        )
        self.assertEqual("a_user", user_id)

        # add another "user_id" caveat, which might allow us to override the
        # user_id.
        macaroon.add_first_party_caveat("user_id = b_user")

        with self.assertRaises(synapse.api.errors.AuthError):
            yield defer.ensureDeferred(
                self.auth_handler.validate_short_term_login_token_and_get_user_id(
                    macaroon.serialize()
                )
            )

    @defer.inlineCallbacks
    def test_mau_limits_disabled(self):
        self.auth_blocking._limit_usage_by_mau = False
        # Ensure does not throw exception
        yield defer.ensureDeferred(
            self.auth_handler.get_access_token_for_user_id(
                "user_a", device_id=None, valid_until_ms=None
            )
        )

        yield defer.ensureDeferred(
            self.auth_handler.validate_short_term_login_token_and_get_user_id(
                self._get_macaroon().serialize()
            )
        )

    @defer.inlineCallbacks
    def test_mau_limits_exceeded_large(self):
        self.auth_blocking._limit_usage_by_mau = True
        self.hs.get_datastore().get_monthly_active_count = Mock(
            return_value=defer.succeed(self.large_number_of_users)
        )

        with self.assertRaises(ResourceLimitError):
            yield defer.ensureDeferred(
                self.auth_handler.get_access_token_for_user_id(
                    "user_a", device_id=None, valid_until_ms=None
                )
            )

        self.hs.get_datastore().get_monthly_active_count = Mock(
            return_value=defer.succeed(self.large_number_of_users)
        )
        with self.assertRaises(ResourceLimitError):
            yield defer.ensureDeferred(
                self.auth_handler.validate_short_term_login_token_and_get_user_id(
                    self._get_macaroon().serialize()
                )
            )

    @defer.inlineCallbacks
    def test_mau_limits_parity(self):
        self.auth_blocking._limit_usage_by_mau = True

        # If not in monthly active cohort
        self.hs.get_datastore().get_monthly_active_count = Mock(
            return_value=defer.succeed(self.auth_blocking._max_mau_value)
        )
        with self.assertRaises(ResourceLimitError):
            yield defer.ensureDeferred(
                self.auth_handler.get_access_token_for_user_id(
                    "user_a", device_id=None, valid_until_ms=None
                )
            )

        self.hs.get_datastore().get_monthly_active_count = Mock(
            return_value=defer.succeed(self.auth_blocking._max_mau_value)
        )
        with self.assertRaises(ResourceLimitError):
            yield defer.ensureDeferred(
                self.auth_handler.validate_short_term_login_token_and_get_user_id(
                    self._get_macaroon().serialize()
                )
            )
        # If in monthly active cohort
        self.hs.get_datastore().user_last_seen_monthly_active = Mock(
            return_value=defer.succeed(self.hs.get_clock().time_msec())
        )
        self.hs.get_datastore().get_monthly_active_count = Mock(
            return_value=defer.succeed(self.auth_blocking._max_mau_value)
        )
        yield defer.ensureDeferred(
            self.auth_handler.get_access_token_for_user_id(
                "user_a", device_id=None, valid_until_ms=None
            )
        )
        self.hs.get_datastore().user_last_seen_monthly_active = Mock(
            return_value=defer.succeed(self.hs.get_clock().time_msec())
        )
        self.hs.get_datastore().get_monthly_active_count = Mock(
            return_value=defer.succeed(self.auth_blocking._max_mau_value)
        )
        yield defer.ensureDeferred(
            self.auth_handler.validate_short_term_login_token_and_get_user_id(
                self._get_macaroon().serialize()
            )
        )

    @defer.inlineCallbacks
    def test_mau_limits_not_exceeded(self):
        self.auth_blocking._limit_usage_by_mau = True

        self.hs.get_datastore().get_monthly_active_count = Mock(
            return_value=defer.succeed(self.small_number_of_users)
        )
        # Ensure does not raise exception
        yield defer.ensureDeferred(
            self.auth_handler.get_access_token_for_user_id(
                "user_a", device_id=None, valid_until_ms=None
            )
        )

        self.hs.get_datastore().get_monthly_active_count = Mock(
            return_value=defer.succeed(self.small_number_of_users)
        )
        yield defer.ensureDeferred(
            self.auth_handler.validate_short_term_login_token_and_get_user_id(
                self._get_macaroon().serialize()
            )
        )

    def _get_macaroon(self):
        token = self.macaroon_generator.generate_short_term_login_token("user_a", 5000)
        return pymacaroons.Macaroon.deserialize(token)
