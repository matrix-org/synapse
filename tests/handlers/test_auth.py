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
from unittest.mock import Mock

import pymacaroons

from twisted.test.proto_helpers import MemoryReactor

from synapse.api.errors import AuthError, ResourceLimitError
from synapse.rest import admin
from synapse.server import HomeServer
from synapse.util import Clock

from tests import unittest
from tests.test_utils import make_awaitable


class AuthTestCase(unittest.HomeserverTestCase):
    servlets = [
        admin.register_servlets,
    ]

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self.auth_handler = hs.get_auth_handler()
        self.macaroon_generator = hs.get_macaroon_generator()

        # MAU tests
        # AuthBlocking reads from the hs' config on initialization. We need to
        # modify its config instead of the hs'
        self.auth_blocking = hs.get_auth_blocking()
        self.auth_blocking._max_mau_value = 50

        self.small_number_of_users = 1
        self.large_number_of_users = 100

        self.user1 = self.register_user("a_user", "pass")

    def test_macaroon_caveats(self) -> None:
        token = self.macaroon_generator.generate_guest_access_token("a_user")
        macaroon = pymacaroons.Macaroon.deserialize(token)

        def verify_gen(caveat: str) -> bool:
            return caveat == "gen = 1"

        def verify_user(caveat: str) -> bool:
            return caveat == "user_id = a_user"

        def verify_type(caveat: str) -> bool:
            return caveat == "type = access"

        def verify_nonce(caveat: str) -> bool:
            return caveat.startswith("nonce =")

        def verify_guest(caveat: str) -> bool:
            return caveat == "guest = true"

        v = pymacaroons.Verifier()
        v.satisfy_general(verify_gen)
        v.satisfy_general(verify_user)
        v.satisfy_general(verify_type)
        v.satisfy_general(verify_nonce)
        v.satisfy_general(verify_guest)
        v.verify(macaroon, self.hs.config.key.macaroon_secret_key)

    def test_short_term_login_token_gives_user_id(self) -> None:
        token = self.macaroon_generator.generate_short_term_login_token(
            self.user1, "", duration_in_ms=5000
        )
        res = self.get_success(self.auth_handler.validate_short_term_login_token(token))
        self.assertEqual(self.user1, res.user_id)
        self.assertEqual("", res.auth_provider_id)

        # when we advance the clock, the token should be rejected
        self.reactor.advance(6)
        self.get_failure(
            self.auth_handler.validate_short_term_login_token(token),
            AuthError,
        )

    def test_short_term_login_token_gives_auth_provider(self) -> None:
        token = self.macaroon_generator.generate_short_term_login_token(
            self.user1, auth_provider_id="my_idp"
        )
        res = self.get_success(self.auth_handler.validate_short_term_login_token(token))
        self.assertEqual(self.user1, res.user_id)
        self.assertEqual("my_idp", res.auth_provider_id)

    def test_short_term_login_token_cannot_replace_user_id(self) -> None:
        token = self.macaroon_generator.generate_short_term_login_token(
            self.user1, "", duration_in_ms=5000
        )
        macaroon = pymacaroons.Macaroon.deserialize(token)

        res = self.get_success(
            self.auth_handler.validate_short_term_login_token(macaroon.serialize())
        )
        self.assertEqual(self.user1, res.user_id)

        # add another "user_id" caveat, which might allow us to override the
        # user_id.
        macaroon.add_first_party_caveat("user_id = b_user")

        self.get_failure(
            self.auth_handler.validate_short_term_login_token(macaroon.serialize()),
            AuthError,
        )

    def test_mau_limits_disabled(self) -> None:
        self.auth_blocking._limit_usage_by_mau = False
        # Ensure does not throw exception
        self.get_success(
            self.auth_handler.create_access_token_for_user_id(
                self.user1, device_id=None, valid_until_ms=None
            )
        )

        self.get_success(
            self.auth_handler.validate_short_term_login_token(
                self._get_macaroon().serialize()
            )
        )

    def test_mau_limits_exceeded_large(self) -> None:
        self.auth_blocking._limit_usage_by_mau = True
        self.hs.get_datastores().main.get_monthly_active_count = Mock(
            return_value=make_awaitable(self.large_number_of_users)
        )

        self.get_failure(
            self.auth_handler.create_access_token_for_user_id(
                self.user1, device_id=None, valid_until_ms=None
            ),
            ResourceLimitError,
        )

        self.hs.get_datastores().main.get_monthly_active_count = Mock(
            return_value=make_awaitable(self.large_number_of_users)
        )
        self.get_failure(
            self.auth_handler.validate_short_term_login_token(
                self._get_macaroon().serialize()
            ),
            ResourceLimitError,
        )

    def test_mau_limits_parity(self) -> None:
        # Ensure we're not at the unix epoch.
        self.reactor.advance(1)
        self.auth_blocking._limit_usage_by_mau = True

        # Set the server to be at the edge of too many users.
        self.hs.get_datastores().main.get_monthly_active_count = Mock(
            return_value=make_awaitable(self.auth_blocking._max_mau_value)
        )

        # If not in monthly active cohort
        self.get_failure(
            self.auth_handler.create_access_token_for_user_id(
                self.user1, device_id=None, valid_until_ms=None
            ),
            ResourceLimitError,
        )
        self.get_failure(
            self.auth_handler.validate_short_term_login_token(
                self._get_macaroon().serialize()
            ),
            ResourceLimitError,
        )

        # If in monthly active cohort
        self.hs.get_datastores().main.user_last_seen_monthly_active = Mock(
            return_value=make_awaitable(self.clock.time_msec())
        )
        self.get_success(
            self.auth_handler.create_access_token_for_user_id(
                self.user1, device_id=None, valid_until_ms=None
            )
        )
        self.get_success(
            self.auth_handler.validate_short_term_login_token(
                self._get_macaroon().serialize()
            )
        )

    def test_mau_limits_not_exceeded(self) -> None:
        self.auth_blocking._limit_usage_by_mau = True

        self.hs.get_datastores().main.get_monthly_active_count = Mock(
            return_value=make_awaitable(self.small_number_of_users)
        )
        # Ensure does not raise exception
        self.get_success(
            self.auth_handler.create_access_token_for_user_id(
                self.user1, device_id=None, valid_until_ms=None
            )
        )

        self.hs.get_datastores().main.get_monthly_active_count = Mock(
            return_value=make_awaitable(self.small_number_of_users)
        )
        self.get_success(
            self.auth_handler.validate_short_term_login_token(
                self._get_macaroon().serialize()
            )
        )

    def _get_macaroon(self) -> pymacaroons.Macaroon:
        token = self.macaroon_generator.generate_short_term_login_token(
            self.user1, "", duration_in_ms=5000
        )
        return pymacaroons.Macaroon.deserialize(token)
