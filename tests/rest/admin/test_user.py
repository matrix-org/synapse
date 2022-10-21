# Copyright 2018-2022 The Matrix.org Foundation C.I.C.
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

import hashlib
import hmac
import os
import urllib.parse
from binascii import unhexlify
from typing import List, Optional
from unittest.mock import Mock, patch

from parameterized import parameterized, parameterized_class

from twisted.test.proto_helpers import MemoryReactor

import synapse.rest.admin
from synapse.api.constants import ApprovalNoticeMedium, LoginType, UserTypes
from synapse.api.errors import Codes, HttpResponseException, ResourceLimitError
from synapse.api.room_versions import RoomVersions
from synapse.rest.client import devices, login, logout, profile, register, room, sync
from synapse.rest.media.v1.filepath import MediaFilePaths
from synapse.server import HomeServer
from synapse.types import JsonDict, UserID, create_requester
from synapse.util import Clock

from tests import unittest
from tests.server import FakeSite, make_request
from tests.test_utils import SMALL_PNG, make_awaitable
from tests.unittest import override_config


class UserRegisterTestCase(unittest.HomeserverTestCase):

    servlets = [
        synapse.rest.admin.register_servlets_for_client_rest_resource,
        profile.register_servlets,
    ]

    def make_homeserver(self, reactor: MemoryReactor, clock: Clock) -> HomeServer:

        self.url = "/_synapse/admin/v1/register"

        self.registration_handler = Mock()
        self.identity_handler = Mock()
        self.login_handler = Mock()
        self.device_handler = Mock()
        self.device_handler.check_device_registered = Mock(return_value="FAKE")

        self.datastore = Mock(return_value=Mock())
        self.datastore.get_current_state_deltas = Mock(return_value=(0, []))

        self.hs = self.setup_test_homeserver()

        self.hs.config.registration.registration_shared_secret = "shared"

        self.hs.get_media_repository = Mock()  # type: ignore[assignment]
        self.hs.get_deactivate_account_handler = Mock()  # type: ignore[assignment]

        return self.hs

    def test_disabled(self) -> None:
        """
        If there is no shared secret, registration through this method will be
        prevented.
        """
        self.hs.config.registration.registration_shared_secret = None

        channel = self.make_request("POST", self.url, b"{}")

        self.assertEqual(400, channel.code, msg=channel.json_body)
        self.assertEqual(
            "Shared secret registration is not enabled", channel.json_body["error"]
        )

    def test_get_nonce(self) -> None:
        """
        Calling GET on the endpoint will return a randomised nonce, using the
        homeserver's secrets provider.
        """
        with patch("secrets.token_hex") as token_hex:
            # Patch secrets.token_hex for the duration of this context
            token_hex.return_value = "abcd"

            channel = self.make_request("GET", self.url)

            self.assertEqual(channel.json_body, {"nonce": "abcd"})

    def test_expired_nonce(self) -> None:
        """
        Calling GET on the endpoint will return a randomised nonce, which will
        only last for SALT_TIMEOUT (60s).
        """
        channel = self.make_request("GET", self.url)
        nonce = channel.json_body["nonce"]

        # 59 seconds
        self.reactor.advance(59)

        body = {"nonce": nonce}
        channel = self.make_request("POST", self.url, body)

        self.assertEqual(400, channel.code, msg=channel.json_body)
        self.assertEqual("username must be specified", channel.json_body["error"])

        # 61 seconds
        self.reactor.advance(2)

        channel = self.make_request("POST", self.url, body)

        self.assertEqual(400, channel.code, msg=channel.json_body)
        self.assertEqual("unrecognised nonce", channel.json_body["error"])

    def test_register_incorrect_nonce(self) -> None:
        """
        Only the provided nonce can be used, as it's checked in the MAC.
        """
        channel = self.make_request("GET", self.url)
        nonce = channel.json_body["nonce"]

        want_mac = hmac.new(key=b"shared", digestmod=hashlib.sha1)
        want_mac.update(b"notthenonce\x00bob\x00abc123\x00admin")
        want_mac_str = want_mac.hexdigest()

        body = {
            "nonce": nonce,
            "username": "bob",
            "password": "abc123",
            "admin": True,
            "mac": want_mac_str,
        }
        channel = self.make_request("POST", self.url, body)

        self.assertEqual(403, channel.code, msg=channel.json_body)
        self.assertEqual("HMAC incorrect", channel.json_body["error"])

    def test_register_correct_nonce(self) -> None:
        """
        When the correct nonce is provided, and the right key is provided, the
        user is registered.
        """
        channel = self.make_request("GET", self.url)
        nonce = channel.json_body["nonce"]

        want_mac = hmac.new(key=b"shared", digestmod=hashlib.sha1)
        want_mac.update(
            nonce.encode("ascii") + b"\x00bob\x00abc123\x00admin\x00support"
        )
        want_mac_str = want_mac.hexdigest()

        body = {
            "nonce": nonce,
            "username": "bob",
            "password": "abc123",
            "admin": True,
            "user_type": UserTypes.SUPPORT,
            "mac": want_mac_str,
        }
        channel = self.make_request("POST", self.url, body)

        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual("@bob:test", channel.json_body["user_id"])

    def test_nonce_reuse(self) -> None:
        """
        A valid unrecognised nonce.
        """
        channel = self.make_request("GET", self.url)
        nonce = channel.json_body["nonce"]

        want_mac = hmac.new(key=b"shared", digestmod=hashlib.sha1)
        want_mac.update(nonce.encode("ascii") + b"\x00bob\x00abc123\x00admin")
        want_mac_str = want_mac.hexdigest()

        body = {
            "nonce": nonce,
            "username": "bob",
            "password": "abc123",
            "admin": True,
            "mac": want_mac_str,
        }
        channel = self.make_request("POST", self.url, body)

        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual("@bob:test", channel.json_body["user_id"])

        # Now, try and reuse it
        channel = self.make_request("POST", self.url, body)

        self.assertEqual(400, channel.code, msg=channel.json_body)
        self.assertEqual("unrecognised nonce", channel.json_body["error"])

    def test_missing_parts(self) -> None:
        """
        Synapse will complain if you don't give nonce, username, password, and
        mac.  Admin and user_types are optional.  Additional checks are done for length
        and type.
        """

        def nonce() -> str:
            channel = self.make_request("GET", self.url)
            return channel.json_body["nonce"]

        #
        # Nonce check
        #

        # Must be an empty body present
        channel = self.make_request("POST", self.url, {})

        self.assertEqual(400, channel.code, msg=channel.json_body)
        self.assertEqual("nonce must be specified", channel.json_body["error"])

        #
        # Username checks
        #

        # Must be present
        channel = self.make_request("POST", self.url, {"nonce": nonce()})

        self.assertEqual(400, channel.code, msg=channel.json_body)
        self.assertEqual("username must be specified", channel.json_body["error"])

        # Must be a string
        body = {"nonce": nonce(), "username": 1234}
        channel = self.make_request("POST", self.url, body)

        self.assertEqual(400, channel.code, msg=channel.json_body)
        self.assertEqual("Invalid username", channel.json_body["error"])

        # Must not have null bytes
        body = {"nonce": nonce(), "username": "abcd\u0000"}
        channel = self.make_request("POST", self.url, body)

        self.assertEqual(400, channel.code, msg=channel.json_body)
        self.assertEqual("Invalid username", channel.json_body["error"])

        # Must not have null bytes
        body = {"nonce": nonce(), "username": "a" * 1000}
        channel = self.make_request("POST", self.url, body)

        self.assertEqual(400, channel.code, msg=channel.json_body)
        self.assertEqual("Invalid username", channel.json_body["error"])

        #
        # Password checks
        #

        # Must be present
        body = {"nonce": nonce(), "username": "a"}
        channel = self.make_request("POST", self.url, body)

        self.assertEqual(400, channel.code, msg=channel.json_body)
        self.assertEqual("password must be specified", channel.json_body["error"])

        # Must be a string
        body = {"nonce": nonce(), "username": "a", "password": 1234}
        channel = self.make_request("POST", self.url, body)

        self.assertEqual(400, channel.code, msg=channel.json_body)
        self.assertEqual("Invalid password", channel.json_body["error"])

        # Must not have null bytes
        body = {"nonce": nonce(), "username": "a", "password": "abcd\u0000"}
        channel = self.make_request("POST", self.url, body)

        self.assertEqual(400, channel.code, msg=channel.json_body)
        self.assertEqual("Invalid password", channel.json_body["error"])

        # Super long
        body = {"nonce": nonce(), "username": "a", "password": "A" * 1000}
        channel = self.make_request("POST", self.url, body)

        self.assertEqual(400, channel.code, msg=channel.json_body)
        self.assertEqual("Invalid password", channel.json_body["error"])

        #
        # user_type check
        #

        # Invalid user_type
        body = {
            "nonce": nonce(),
            "username": "a",
            "password": "1234",
            "user_type": "invalid",
        }
        channel = self.make_request("POST", self.url, body)

        self.assertEqual(400, channel.code, msg=channel.json_body)
        self.assertEqual("Invalid user type", channel.json_body["error"])

    def test_displayname(self) -> None:
        """
        Test that displayname of new user is set
        """

        # set no displayname
        channel = self.make_request("GET", self.url)
        nonce = channel.json_body["nonce"]

        want_mac = hmac.new(key=b"shared", digestmod=hashlib.sha1)
        want_mac.update(nonce.encode("ascii") + b"\x00bob1\x00abc123\x00notadmin")
        want_mac_str = want_mac.hexdigest()

        body = {
            "nonce": nonce,
            "username": "bob1",
            "password": "abc123",
            "mac": want_mac_str,
        }

        channel = self.make_request("POST", self.url, body)

        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual("@bob1:test", channel.json_body["user_id"])

        channel = self.make_request("GET", "/profile/@bob1:test/displayname")
        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual("bob1", channel.json_body["displayname"])

        # displayname is None
        channel = self.make_request("GET", self.url)
        nonce = channel.json_body["nonce"]

        want_mac = hmac.new(key=b"shared", digestmod=hashlib.sha1)
        want_mac.update(nonce.encode("ascii") + b"\x00bob2\x00abc123\x00notadmin")
        want_mac_str = want_mac.hexdigest()

        body = {
            "nonce": nonce,
            "username": "bob2",
            "displayname": None,
            "password": "abc123",
            "mac": want_mac_str,
        }
        channel = self.make_request("POST", self.url, body)

        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual("@bob2:test", channel.json_body["user_id"])

        channel = self.make_request("GET", "/profile/@bob2:test/displayname")
        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual("bob2", channel.json_body["displayname"])

        # displayname is empty
        channel = self.make_request("GET", self.url)
        nonce = channel.json_body["nonce"]

        want_mac = hmac.new(key=b"shared", digestmod=hashlib.sha1)
        want_mac.update(nonce.encode("ascii") + b"\x00bob3\x00abc123\x00notadmin")
        want_mac_str = want_mac.hexdigest()

        body = {
            "nonce": nonce,
            "username": "bob3",
            "displayname": "",
            "password": "abc123",
            "mac": want_mac_str,
        }
        channel = self.make_request("POST", self.url, body)

        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual("@bob3:test", channel.json_body["user_id"])

        channel = self.make_request("GET", "/profile/@bob3:test/displayname")
        self.assertEqual(404, channel.code, msg=channel.json_body)

        # set displayname
        channel = self.make_request("GET", self.url)
        nonce = channel.json_body["nonce"]

        want_mac = hmac.new(key=b"shared", digestmod=hashlib.sha1)
        want_mac.update(nonce.encode("ascii") + b"\x00bob4\x00abc123\x00notadmin")
        want_mac_str = want_mac.hexdigest()

        body = {
            "nonce": nonce,
            "username": "bob4",
            "displayname": "Bob's Name",
            "password": "abc123",
            "mac": want_mac_str,
        }
        channel = self.make_request("POST", self.url, body)

        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual("@bob4:test", channel.json_body["user_id"])

        channel = self.make_request("GET", "/profile/@bob4:test/displayname")
        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual("Bob's Name", channel.json_body["displayname"])

    @override_config(
        {"limit_usage_by_mau": True, "max_mau_value": 2, "mau_trial_days": 0}
    )
    def test_register_mau_limit_reached(self) -> None:
        """
        Check we can register a user via the shared secret registration API
        even if the MAU limit is reached.
        """
        handler = self.hs.get_registration_handler()
        store = self.hs.get_datastores().main

        # Set monthly active users to the limit
        store.get_monthly_active_count = Mock(
            return_value=make_awaitable(self.hs.config.server.max_mau_value)
        )
        # Check that the blocking of monthly active users is working as expected
        # The registration of a new user fails due to the limit
        self.get_failure(
            handler.register_user(localpart="local_part"), ResourceLimitError
        )

        # Register new user with admin API
        channel = self.make_request("GET", self.url)
        nonce = channel.json_body["nonce"]

        want_mac = hmac.new(key=b"shared", digestmod=hashlib.sha1)
        want_mac.update(
            nonce.encode("ascii") + b"\x00bob\x00abc123\x00admin\x00support"
        )
        want_mac_str = want_mac.hexdigest()

        body = {
            "nonce": nonce,
            "username": "bob",
            "password": "abc123",
            "admin": True,
            "user_type": UserTypes.SUPPORT,
            "mac": want_mac_str,
        }
        channel = self.make_request("POST", self.url, body)

        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual("@bob:test", channel.json_body["user_id"])


class UsersListTestCase(unittest.HomeserverTestCase):

    servlets = [
        synapse.rest.admin.register_servlets,
        login.register_servlets,
    ]
    url = "/_synapse/admin/v2/users"

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self.store = hs.get_datastores().main

        self.admin_user = self.register_user("admin", "pass", admin=True)
        self.admin_user_tok = self.login("admin", "pass")

    def test_no_auth(self) -> None:
        """
        Try to list users without authentication.
        """
        channel = self.make_request("GET", self.url, b"{}")

        self.assertEqual(401, channel.code, msg=channel.json_body)
        self.assertEqual(Codes.MISSING_TOKEN, channel.json_body["errcode"])

    def test_requester_is_no_admin(self) -> None:
        """
        If the user is not a server admin, an error is returned.
        """
        self._create_users(1)
        other_user_token = self.login("user1", "pass1")

        channel = self.make_request("GET", self.url, access_token=other_user_token)

        self.assertEqual(403, channel.code, msg=channel.json_body)
        self.assertEqual(Codes.FORBIDDEN, channel.json_body["errcode"])

    def test_all_users(self) -> None:
        """
        List all users, including deactivated users.
        """
        self._create_users(2)

        channel = self.make_request(
            "GET",
            self.url + "?deactivated=true",
            {},
            access_token=self.admin_user_tok,
        )

        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual(3, len(channel.json_body["users"]))
        self.assertEqual(3, channel.json_body["total"])

        # Check that all fields are available
        self._check_fields(channel.json_body["users"])

    def test_search_term(self) -> None:
        """Test that searching for a users works correctly"""

        def _search_test(
            expected_user_id: Optional[str],
            search_term: str,
            search_field: Optional[str] = "name",
            expected_http_code: Optional[int] = 200,
        ) -> None:
            """Search for a user and check that the returned user's id is a match

            Args:
                expected_user_id: The user_id expected to be returned by the API. Set
                    to None to expect zero results for the search
                search_term: The term to search for user names with
                search_field: Field which is to request: `name` or `user_id`
                expected_http_code: The expected http code for the request
            """
            url = self.url + "?%s=%s" % (
                search_field,
                search_term,
            )
            channel = self.make_request(
                "GET",
                url,
                access_token=self.admin_user_tok,
            )
            self.assertEqual(expected_http_code, channel.code, msg=channel.json_body)

            if expected_http_code != 200:
                return

            # Check that users were returned
            self.assertTrue("users" in channel.json_body)
            self._check_fields(channel.json_body["users"])
            users = channel.json_body["users"]

            # Check that the expected number of users were returned
            expected_user_count = 1 if expected_user_id else 0
            self.assertEqual(len(users), expected_user_count)
            self.assertEqual(channel.json_body["total"], expected_user_count)

            if expected_user_id:
                # Check that the first returned user id is correct
                u = users[0]
                self.assertEqual(expected_user_id, u["name"])

        self._create_users(2)

        user1 = "@user1:test"
        user2 = "@user2:test"

        # Perform search tests
        _search_test(user1, "er1")
        _search_test(user1, "me 1")

        _search_test(user2, "er2")
        _search_test(user2, "me 2")

        _search_test(user1, "er1", "user_id")
        _search_test(user2, "er2", "user_id")

        # Test case insensitive
        _search_test(user1, "ER1")
        _search_test(user1, "NAME 1")

        _search_test(user2, "ER2")
        _search_test(user2, "NAME 2")

        _search_test(user1, "ER1", "user_id")
        _search_test(user2, "ER2", "user_id")

        _search_test(None, "foo")
        _search_test(None, "bar")

        _search_test(None, "foo", "user_id")
        _search_test(None, "bar", "user_id")

    @override_config(
        {
            "experimental_features": {
                "msc3866": {
                    "enabled": True,
                    "require_approval_for_new_accounts": True,
                }
            }
        }
    )
    def test_invalid_parameter(self) -> None:
        """
        If parameters are invalid, an error is returned.
        """

        # negative limit
        channel = self.make_request(
            "GET",
            self.url + "?limit=-5",
            access_token=self.admin_user_tok,
        )

        self.assertEqual(400, channel.code, msg=channel.json_body)
        self.assertEqual(Codes.INVALID_PARAM, channel.json_body["errcode"])

        # negative from
        channel = self.make_request(
            "GET",
            self.url + "?from=-5",
            access_token=self.admin_user_tok,
        )

        self.assertEqual(400, channel.code, msg=channel.json_body)
        self.assertEqual(Codes.INVALID_PARAM, channel.json_body["errcode"])

        # invalid guests
        channel = self.make_request(
            "GET",
            self.url + "?guests=not_bool",
            access_token=self.admin_user_tok,
        )

        self.assertEqual(400, channel.code, msg=channel.json_body)
        self.assertEqual(Codes.INVALID_PARAM, channel.json_body["errcode"])

        # invalid deactivated
        channel = self.make_request(
            "GET",
            self.url + "?deactivated=not_bool",
            access_token=self.admin_user_tok,
        )

        self.assertEqual(400, channel.code, msg=channel.json_body)
        self.assertEqual(Codes.INVALID_PARAM, channel.json_body["errcode"])

        # invalid approved
        channel = self.make_request(
            "GET",
            self.url + "?approved=not_bool",
            access_token=self.admin_user_tok,
        )

        self.assertEqual(400, channel.code, msg=channel.json_body)
        self.assertEqual(Codes.INVALID_PARAM, channel.json_body["errcode"])

        # unkown order_by
        channel = self.make_request(
            "GET",
            self.url + "?order_by=bar",
            access_token=self.admin_user_tok,
        )

        self.assertEqual(400, channel.code, msg=channel.json_body)
        self.assertEqual(Codes.INVALID_PARAM, channel.json_body["errcode"])

        # invalid search order
        channel = self.make_request(
            "GET",
            self.url + "?dir=bar",
            access_token=self.admin_user_tok,
        )

        self.assertEqual(400, channel.code, msg=channel.json_body)
        self.assertEqual(Codes.INVALID_PARAM, channel.json_body["errcode"])

    def test_limit(self) -> None:
        """
        Testing list of users with limit
        """

        number_users = 20
        # Create one less user (since there's already an admin user).
        self._create_users(number_users - 1)

        channel = self.make_request(
            "GET",
            self.url + "?limit=5",
            access_token=self.admin_user_tok,
        )

        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual(channel.json_body["total"], number_users)
        self.assertEqual(len(channel.json_body["users"]), 5)
        self.assertEqual(channel.json_body["next_token"], "5")
        self._check_fields(channel.json_body["users"])

    def test_from(self) -> None:
        """
        Testing list of users with a defined starting point (from)
        """

        number_users = 20
        # Create one less user (since there's already an admin user).
        self._create_users(number_users - 1)

        channel = self.make_request(
            "GET",
            self.url + "?from=5",
            access_token=self.admin_user_tok,
        )

        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual(channel.json_body["total"], number_users)
        self.assertEqual(len(channel.json_body["users"]), 15)
        self.assertNotIn("next_token", channel.json_body)
        self._check_fields(channel.json_body["users"])

    def test_limit_and_from(self) -> None:
        """
        Testing list of users with a defined starting point and limit
        """

        number_users = 20
        # Create one less user (since there's already an admin user).
        self._create_users(number_users - 1)

        channel = self.make_request(
            "GET",
            self.url + "?from=5&limit=10",
            access_token=self.admin_user_tok,
        )

        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual(channel.json_body["total"], number_users)
        self.assertEqual(channel.json_body["next_token"], "15")
        self.assertEqual(len(channel.json_body["users"]), 10)
        self._check_fields(channel.json_body["users"])

    def test_next_token(self) -> None:
        """
        Testing that `next_token` appears at the right place
        """

        number_users = 20
        # Create one less user (since there's already an admin user).
        self._create_users(number_users - 1)

        #  `next_token` does not appear
        # Number of results is the number of entries
        channel = self.make_request(
            "GET",
            self.url + "?limit=20",
            access_token=self.admin_user_tok,
        )

        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual(channel.json_body["total"], number_users)
        self.assertEqual(len(channel.json_body["users"]), number_users)
        self.assertNotIn("next_token", channel.json_body)

        #  `next_token` does not appear
        # Number of max results is larger than the number of entries
        channel = self.make_request(
            "GET",
            self.url + "?limit=21",
            access_token=self.admin_user_tok,
        )

        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual(channel.json_body["total"], number_users)
        self.assertEqual(len(channel.json_body["users"]), number_users)
        self.assertNotIn("next_token", channel.json_body)

        #  `next_token` does appear
        # Number of max results is smaller than the number of entries
        channel = self.make_request(
            "GET",
            self.url + "?limit=19",
            access_token=self.admin_user_tok,
        )

        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual(channel.json_body["total"], number_users)
        self.assertEqual(len(channel.json_body["users"]), 19)
        self.assertEqual(channel.json_body["next_token"], "19")

        # Check
        # Set `from` to value of `next_token` for request remaining entries
        #  `next_token` does not appear
        channel = self.make_request(
            "GET",
            self.url + "?from=19",
            access_token=self.admin_user_tok,
        )

        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual(channel.json_body["total"], number_users)
        self.assertEqual(len(channel.json_body["users"]), 1)
        self.assertNotIn("next_token", channel.json_body)

    def test_order_by(self) -> None:
        """
        Testing order list with parameter `order_by`
        """

        # make sure that the users do not have the same timestamps
        self.reactor.advance(10)
        user1 = self.register_user("user1", "pass1", admin=False, displayname="Name Z")
        self.reactor.advance(10)
        user2 = self.register_user("user2", "pass2", admin=False, displayname="Name Y")

        # Modify user
        self.get_success(self.store.set_user_deactivated_status(user1, True))
        self.get_success(self.store.set_shadow_banned(UserID.from_string(user1), True))

        # Set avatar URL to all users, that no user has a NULL value to avoid
        # different sort order between SQlite and PostreSQL
        self.get_success(self.store.set_profile_avatar_url("user1", "mxc://url3"))
        self.get_success(self.store.set_profile_avatar_url("user2", "mxc://url2"))
        self.get_success(self.store.set_profile_avatar_url("admin", "mxc://url1"))

        # order by default (name)
        self._order_test([self.admin_user, user1, user2], None)
        self._order_test([self.admin_user, user1, user2], None, "f")
        self._order_test([user2, user1, self.admin_user], None, "b")

        # order by name
        self._order_test([self.admin_user, user1, user2], "name")
        self._order_test([self.admin_user, user1, user2], "name", "f")
        self._order_test([user2, user1, self.admin_user], "name", "b")

        # order by displayname
        self._order_test([user2, user1, self.admin_user], "displayname")
        self._order_test([user2, user1, self.admin_user], "displayname", "f")
        self._order_test([self.admin_user, user1, user2], "displayname", "b")

        # order by is_guest
        # like sort by ascending name, as no guest user here
        self._order_test([self.admin_user, user1, user2], "is_guest")
        self._order_test([self.admin_user, user1, user2], "is_guest", "f")
        self._order_test([self.admin_user, user1, user2], "is_guest", "b")

        # order by admin
        self._order_test([user1, user2, self.admin_user], "admin")
        self._order_test([user1, user2, self.admin_user], "admin", "f")
        self._order_test([self.admin_user, user1, user2], "admin", "b")

        # order by deactivated
        self._order_test([self.admin_user, user2, user1], "deactivated")
        self._order_test([self.admin_user, user2, user1], "deactivated", "f")
        self._order_test([user1, self.admin_user, user2], "deactivated", "b")

        # order by user_type
        # like sort by ascending name, as no special user type here
        self._order_test([self.admin_user, user1, user2], "user_type")
        self._order_test([self.admin_user, user1, user2], "user_type", "f")
        self._order_test([self.admin_user, user1, user2], "is_guest", "b")

        # order by shadow_banned
        self._order_test([self.admin_user, user2, user1], "shadow_banned")
        self._order_test([self.admin_user, user2, user1], "shadow_banned", "f")
        self._order_test([user1, self.admin_user, user2], "shadow_banned", "b")

        # order by avatar_url
        self._order_test([self.admin_user, user2, user1], "avatar_url")
        self._order_test([self.admin_user, user2, user1], "avatar_url", "f")
        self._order_test([user1, user2, self.admin_user], "avatar_url", "b")

        # order by creation_ts
        self._order_test([self.admin_user, user1, user2], "creation_ts")
        self._order_test([self.admin_user, user1, user2], "creation_ts", "f")
        self._order_test([user2, user1, self.admin_user], "creation_ts", "b")

    @override_config(
        {
            "experimental_features": {
                "msc3866": {
                    "enabled": True,
                    "require_approval_for_new_accounts": True,
                }
            }
        }
    )
    def test_filter_out_approved(self) -> None:
        """Tests that the endpoint can filter out approved users."""
        # Create our users.
        self._create_users(2)

        # Get the list of users.
        channel = self.make_request(
            "GET",
            self.url,
            access_token=self.admin_user_tok,
        )
        self.assertEqual(200, channel.code, channel.result)

        # Exclude the admin, because we don't want to accidentally un-approve the admin.
        non_admin_user_ids = [
            user["name"]
            for user in channel.json_body["users"]
            if user["name"] != self.admin_user
        ]

        self.assertEqual(2, len(non_admin_user_ids), non_admin_user_ids)

        # Select a user and un-approve them. We do this rather than the other way around
        # because, since these users are created by an admin, we consider them already
        # approved.
        not_approved_user = non_admin_user_ids[0]

        channel = self.make_request(
            "PUT",
            f"/_synapse/admin/v2/users/{not_approved_user}",
            {"approved": False},
            access_token=self.admin_user_tok,
        )
        self.assertEqual(200, channel.code, channel.result)

        # Now get the list of users again, this time filtering out approved users.
        channel = self.make_request(
            "GET",
            self.url + "?approved=false",
            access_token=self.admin_user_tok,
        )
        self.assertEqual(200, channel.code, channel.result)

        non_admin_user_ids = [
            user["name"]
            for user in channel.json_body["users"]
            if user["name"] != self.admin_user
        ]

        # We should only have our unapproved user now.
        self.assertEqual(1, len(non_admin_user_ids), non_admin_user_ids)
        self.assertEqual(not_approved_user, non_admin_user_ids[0])

    def test_erasure_status(self) -> None:
        # Create a new user.
        user_id = self.register_user("eraseme", "eraseme")

        # They should appear in the list users API, marked as not erased.
        channel = self.make_request(
            "GET",
            self.url + "?deactivated=true",
            access_token=self.admin_user_tok,
        )
        users = {user["name"]: user for user in channel.json_body["users"]}
        self.assertIs(users[user_id]["erased"], False)

        # Deactivate that user, requesting erasure.
        deactivate_account_handler = self.hs.get_deactivate_account_handler()
        self.get_success(
            deactivate_account_handler.deactivate_account(
                user_id, erase_data=True, requester=create_requester(user_id)
            )
        )

        # Repeat the list users query. They should now be marked as erased.
        channel = self.make_request(
            "GET",
            self.url + "?deactivated=true",
            access_token=self.admin_user_tok,
        )
        users = {user["name"]: user for user in channel.json_body["users"]}
        self.assertIs(users[user_id]["erased"], True)

    def _order_test(
        self,
        expected_user_list: List[str],
        order_by: Optional[str],
        dir: Optional[str] = None,
    ) -> None:
        """Request the list of users in a certain order. Assert that order is what
        we expect
        Args:
            expected_user_list: The list of user_id in the order we expect to get
                back from the server
            order_by: The type of ordering to give the server
            dir: The direction of ordering to give the server
        """

        url = self.url + "?deactivated=true&"
        if order_by is not None:
            url += "order_by=%s&" % (order_by,)
        if dir is not None and dir in ("b", "f"):
            url += "dir=%s" % (dir,)
        channel = self.make_request(
            "GET",
            url,
            access_token=self.admin_user_tok,
        )
        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual(channel.json_body["total"], len(expected_user_list))

        returned_order = [row["name"] for row in channel.json_body["users"]]
        self.assertEqual(expected_user_list, returned_order)
        self._check_fields(channel.json_body["users"])

    def _check_fields(self, content: List[JsonDict]) -> None:
        """Checks that the expected user attributes are present in content
        Args:
            content: List that is checked for content
        """
        for u in content:
            self.assertIn("name", u)
            self.assertIn("is_guest", u)
            self.assertIn("admin", u)
            self.assertIn("user_type", u)
            self.assertIn("deactivated", u)
            self.assertIn("shadow_banned", u)
            self.assertIn("displayname", u)
            self.assertIn("avatar_url", u)
            self.assertIn("creation_ts", u)

    def _create_users(self, number_users: int) -> None:
        """
        Create a number of users
        Args:
            number_users: Number of users to be created
        """
        for i in range(1, number_users + 1):
            self.register_user(
                "user%d" % i,
                "pass%d" % i,
                admin=False,
                displayname="Name %d" % i,
            )


class UserDevicesTestCase(unittest.HomeserverTestCase):
    """
    Tests user device management-related Admin APIs.
    """

    servlets = [
        synapse.rest.admin.register_servlets,
        login.register_servlets,
        sync.register_servlets,
    ]

    def prepare(
        self, reactor: MemoryReactor, clock: Clock, homeserver: HomeServer
    ) -> None:
        # Set up an Admin user to query the Admin API with.
        self.admin_user_id = self.register_user("admin", "pass", admin=True)
        self.admin_user_token = self.login("admin", "pass")

        # Set up a test user to query the devices of.
        self.other_user_device_id = "TESTDEVICEID"
        self.other_user_device_display_name = "My Test Device"
        self.other_user_client_ip = "1.2.3.4"
        self.other_user_user_agent = "EquestriaTechnology/123.0"

        self.other_user_id = self.register_user("user", "pass", displayname="User1")
        self.other_user_token = self.login(
            "user",
            "pass",
            device_id=self.other_user_device_id,
            additional_request_fields={
                "initial_device_display_name": self.other_user_device_display_name,
            },
        )

        # Have the "other user" make a request so that the "last_seen_*" fields are
        # populated in the tests below.
        channel = self.make_request(
            "GET",
            "/_matrix/client/v3/sync",
            access_token=self.other_user_token,
            client_ip=self.other_user_client_ip,
            custom_headers=[
                ("User-Agent", self.other_user_user_agent),
            ],
        )
        self.assertEqual(200, channel.code, msg=channel.json_body)

    def test_list_user_devices(self) -> None:
        """
        Tests that a user's devices and attributes are listed correctly via the Admin API.
        """
        # Request all devices of "other user"
        channel = self.make_request(
            "GET",
            f"/_synapse/admin/v2/users/{self.other_user_id}/devices",
            access_token=self.admin_user_token,
        )
        self.assertEqual(200, channel.code, msg=channel.json_body)

        # Double-check we got the single device expected
        user_devices = channel.json_body["devices"]
        self.assertEqual(len(user_devices), 1)
        self.assertEqual(channel.json_body["total"], 1)

        # Check that all the attributes of the device reported are as expected.
        self._validate_attributes_of_device_response(user_devices[0])

        # Request just a single device for "other user" by its ID
        channel = self.make_request(
            "GET",
            f"/_synapse/admin/v2/users/{self.other_user_id}/devices/"
            f"{self.other_user_device_id}",
            access_token=self.admin_user_token,
        )
        self.assertEqual(200, channel.code, msg=channel.json_body)

        # Check that all the attributes of the device reported are as expected.
        self._validate_attributes_of_device_response(channel.json_body)

    def _validate_attributes_of_device_response(self, response: JsonDict) -> None:
        # Check that all device expected attributes are present
        self.assertEqual(response["user_id"], self.other_user_id)
        self.assertEqual(response["device_id"], self.other_user_device_id)
        self.assertEqual(response["display_name"], self.other_user_device_display_name)
        self.assertEqual(response["last_seen_ip"], self.other_user_client_ip)
        self.assertEqual(response["last_seen_user_agent"], self.other_user_user_agent)
        self.assertIsInstance(response["last_seen_ts"], int)
        self.assertGreater(response["last_seen_ts"], 0)


class DeactivateAccountTestCase(unittest.HomeserverTestCase):

    servlets = [
        synapse.rest.admin.register_servlets,
        login.register_servlets,
    ]

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self.store = hs.get_datastores().main

        self.admin_user = self.register_user("admin", "pass", admin=True)
        self.admin_user_tok = self.login("admin", "pass")

        self.other_user = self.register_user("user", "pass", displayname="User1")
        self.other_user_token = self.login("user", "pass")
        self.url_other_user = "/_synapse/admin/v2/users/%s" % urllib.parse.quote(
            self.other_user
        )
        self.url = "/_synapse/admin/v1/deactivate/%s" % urllib.parse.quote(
            self.other_user
        )

        # set attributes for user
        self.get_success(
            self.store.set_profile_avatar_url("user", "mxc://servername/mediaid")
        )
        self.get_success(
            self.store.user_add_threepid("@user:test", "email", "foo@bar.com", 0, 0)
        )

    def test_no_auth(self) -> None:
        """
        Try to deactivate users without authentication.
        """
        channel = self.make_request("POST", self.url, b"{}")

        self.assertEqual(401, channel.code, msg=channel.json_body)
        self.assertEqual(Codes.MISSING_TOKEN, channel.json_body["errcode"])

    def test_requester_is_not_admin(self) -> None:
        """
        If the user is not a server admin, an error is returned.
        """
        url = "/_synapse/admin/v1/deactivate/@bob:test"

        channel = self.make_request("POST", url, access_token=self.other_user_token)

        self.assertEqual(403, channel.code, msg=channel.json_body)
        self.assertEqual("You are not a server admin", channel.json_body["error"])

        channel = self.make_request(
            "POST",
            url,
            access_token=self.other_user_token,
            content=b"{}",
        )

        self.assertEqual(403, channel.code, msg=channel.json_body)
        self.assertEqual("You are not a server admin", channel.json_body["error"])

    def test_user_does_not_exist(self) -> None:
        """
        Tests that deactivation for a user that does not exist returns a 404
        """

        channel = self.make_request(
            "POST",
            "/_synapse/admin/v1/deactivate/@unknown_person:test",
            access_token=self.admin_user_tok,
        )

        self.assertEqual(404, channel.code, msg=channel.json_body)
        self.assertEqual(Codes.NOT_FOUND, channel.json_body["errcode"])

    def test_erase_is_not_bool(self) -> None:
        """
        If parameter `erase` is not boolean, return an error
        """

        channel = self.make_request(
            "POST",
            self.url,
            content={"erase": "False"},
            access_token=self.admin_user_tok,
        )

        self.assertEqual(400, channel.code, msg=channel.json_body)
        self.assertEqual(Codes.BAD_JSON, channel.json_body["errcode"])

    def test_user_is_not_local(self) -> None:
        """
        Tests that deactivation for a user that is not a local returns a 400
        """
        url = "/_synapse/admin/v1/deactivate/@unknown_person:unknown_domain"

        channel = self.make_request("POST", url, access_token=self.admin_user_tok)

        self.assertEqual(400, channel.code, msg=channel.json_body)
        self.assertEqual("Can only deactivate local users", channel.json_body["error"])

    def test_deactivate_user_erase_true(self) -> None:
        """
        Test deactivating a user and set `erase` to `true`
        """

        # Get user
        channel = self.make_request(
            "GET",
            self.url_other_user,
            access_token=self.admin_user_tok,
        )

        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual("@user:test", channel.json_body["name"])
        self.assertEqual(False, channel.json_body["deactivated"])
        self.assertEqual("foo@bar.com", channel.json_body["threepids"][0]["address"])
        self.assertEqual("mxc://servername/mediaid", channel.json_body["avatar_url"])
        self.assertEqual("User1", channel.json_body["displayname"])
        self.assertFalse(channel.json_body["erased"])

        # Deactivate and erase user
        channel = self.make_request(
            "POST",
            self.url,
            access_token=self.admin_user_tok,
            content={"erase": True},
        )

        self.assertEqual(200, channel.code, msg=channel.json_body)

        # Get user
        channel = self.make_request(
            "GET",
            self.url_other_user,
            access_token=self.admin_user_tok,
        )

        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual("@user:test", channel.json_body["name"])
        self.assertEqual(True, channel.json_body["deactivated"])
        self.assertEqual(0, len(channel.json_body["threepids"]))
        self.assertIsNone(channel.json_body["avatar_url"])
        self.assertIsNone(channel.json_body["displayname"])
        self.assertTrue(channel.json_body["erased"])

        self._is_erased("@user:test", True)

    @override_config({"max_avatar_size": 1234})
    def test_deactivate_user_erase_true_avatar_nonnull_but_empty(self) -> None:
        """Check we can erase a user whose avatar is the empty string.

        Reproduces #12257.
        """
        # Patch `self.other_user` to have an empty string as their avatar.
        self.get_success(self.store.set_profile_avatar_url("user", ""))

        # Check we can still erase them.
        channel = self.make_request(
            "POST",
            self.url,
            access_token=self.admin_user_tok,
            content={"erase": True},
        )
        self.assertEqual(200, channel.code, msg=channel.json_body)
        self._is_erased("@user:test", True)

    def test_deactivate_user_erase_false(self) -> None:
        """
        Test deactivating a user and set `erase` to `false`
        """

        # Get user
        channel = self.make_request(
            "GET",
            self.url_other_user,
            access_token=self.admin_user_tok,
        )

        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual("@user:test", channel.json_body["name"])
        self.assertEqual(False, channel.json_body["deactivated"])
        self.assertEqual("foo@bar.com", channel.json_body["threepids"][0]["address"])
        self.assertEqual("mxc://servername/mediaid", channel.json_body["avatar_url"])
        self.assertEqual("User1", channel.json_body["displayname"])

        # Deactivate user
        channel = self.make_request(
            "POST",
            self.url,
            access_token=self.admin_user_tok,
            content={"erase": False},
        )

        self.assertEqual(200, channel.code, msg=channel.json_body)

        # Get user
        channel = self.make_request(
            "GET",
            self.url_other_user,
            access_token=self.admin_user_tok,
        )

        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual("@user:test", channel.json_body["name"])
        self.assertEqual(True, channel.json_body["deactivated"])
        self.assertEqual(0, len(channel.json_body["threepids"]))
        self.assertEqual("mxc://servername/mediaid", channel.json_body["avatar_url"])
        self.assertEqual("User1", channel.json_body["displayname"])

        self._is_erased("@user:test", False)

    def test_deactivate_user_erase_true_no_profile(self) -> None:
        """
        Test deactivating a user and set `erase` to `true`
        if user has no profile information (stored in the database table `profiles`).
        """

        # Users normally have an entry in `profiles`, but occasionally they are created without one.
        # To test deactivation for users without a profile, we delete the profile information for our user.
        self.get_success(
            self.store.db_pool.simple_delete_one(
                table="profiles", keyvalues={"user_id": "user"}
            )
        )

        # Get user
        channel = self.make_request(
            "GET",
            self.url_other_user,
            access_token=self.admin_user_tok,
        )

        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual("@user:test", channel.json_body["name"])
        self.assertEqual(False, channel.json_body["deactivated"])
        self.assertEqual("foo@bar.com", channel.json_body["threepids"][0]["address"])
        self.assertIsNone(channel.json_body["avatar_url"])
        self.assertIsNone(channel.json_body["displayname"])

        # Deactivate and erase user
        channel = self.make_request(
            "POST",
            self.url,
            access_token=self.admin_user_tok,
            content={"erase": True},
        )

        self.assertEqual(200, channel.code, msg=channel.json_body)

        # Get user
        channel = self.make_request(
            "GET",
            self.url_other_user,
            access_token=self.admin_user_tok,
        )

        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual("@user:test", channel.json_body["name"])
        self.assertEqual(True, channel.json_body["deactivated"])
        self.assertEqual(0, len(channel.json_body["threepids"]))
        self.assertIsNone(channel.json_body["avatar_url"])
        self.assertIsNone(channel.json_body["displayname"])

        self._is_erased("@user:test", True)

    def _is_erased(self, user_id: str, expect: bool) -> None:
        """Assert that the user is erased or not"""
        d = self.store.is_user_erased(user_id)
        if expect:
            self.assertTrue(self.get_success(d))
        else:
            self.assertFalse(self.get_success(d))


class UserRestTestCase(unittest.HomeserverTestCase):

    servlets = [
        synapse.rest.admin.register_servlets,
        login.register_servlets,
        sync.register_servlets,
        register.register_servlets,
    ]

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self.store = hs.get_datastores().main
        self.auth_handler = hs.get_auth_handler()

        # create users and get access tokens
        # regardless of whether password login or SSO is allowed
        self.admin_user = self.register_user("admin", "pass", admin=True)
        self.admin_user_tok = self.get_success(
            self.auth_handler.create_access_token_for_user_id(
                self.admin_user, device_id=None, valid_until_ms=None
            )
        )

        self.other_user = self.register_user("user", "pass", displayname="User")
        self.other_user_token = self.get_success(
            self.auth_handler.create_access_token_for_user_id(
                self.other_user, device_id=None, valid_until_ms=None
            )
        )

        self.url_prefix = "/_synapse/admin/v2/users/%s"
        self.url_other_user = self.url_prefix % self.other_user

    def test_requester_is_no_admin(self) -> None:
        """
        If the user is not a server admin, an error is returned.
        """
        url = self.url_prefix % "@bob:test"

        channel = self.make_request(
            "GET",
            url,
            access_token=self.other_user_token,
        )

        self.assertEqual(403, channel.code, msg=channel.json_body)
        self.assertEqual("You are not a server admin", channel.json_body["error"])

        channel = self.make_request(
            "PUT",
            url,
            access_token=self.other_user_token,
            content=b"{}",
        )

        self.assertEqual(403, channel.code, msg=channel.json_body)
        self.assertEqual("You are not a server admin", channel.json_body["error"])

    def test_user_does_not_exist(self) -> None:
        """
        Tests that a lookup for a user that does not exist returns a 404
        """

        channel = self.make_request(
            "GET",
            self.url_prefix % "@unknown_person:test",
            access_token=self.admin_user_tok,
        )

        self.assertEqual(404, channel.code, msg=channel.json_body)
        self.assertEqual("M_NOT_FOUND", channel.json_body["errcode"])

    def test_invalid_parameter(self) -> None:
        """
        If parameters are invalid, an error is returned.
        """

        # admin not bool
        channel = self.make_request(
            "PUT",
            self.url_other_user,
            access_token=self.admin_user_tok,
            content={"admin": "not_bool"},
        )
        self.assertEqual(400, channel.code, msg=channel.json_body)
        self.assertEqual(Codes.BAD_JSON, channel.json_body["errcode"])

        # deactivated not bool
        channel = self.make_request(
            "PUT",
            self.url_other_user,
            access_token=self.admin_user_tok,
            content={"deactivated": "not_bool"},
        )
        self.assertEqual(400, channel.code, msg=channel.json_body)
        self.assertEqual(Codes.UNKNOWN, channel.json_body["errcode"])

        # password not str
        channel = self.make_request(
            "PUT",
            self.url_other_user,
            access_token=self.admin_user_tok,
            content={"password": True},
        )
        self.assertEqual(400, channel.code, msg=channel.json_body)
        self.assertEqual(Codes.UNKNOWN, channel.json_body["errcode"])

        # password not length
        channel = self.make_request(
            "PUT",
            self.url_other_user,
            access_token=self.admin_user_tok,
            content={"password": "x" * 513},
        )
        self.assertEqual(400, channel.code, msg=channel.json_body)
        self.assertEqual(Codes.UNKNOWN, channel.json_body["errcode"])

        # user_type not valid
        channel = self.make_request(
            "PUT",
            self.url_other_user,
            access_token=self.admin_user_tok,
            content={"user_type": "new type"},
        )
        self.assertEqual(400, channel.code, msg=channel.json_body)
        self.assertEqual(Codes.UNKNOWN, channel.json_body["errcode"])

        # external_ids not valid
        channel = self.make_request(
            "PUT",
            self.url_other_user,
            access_token=self.admin_user_tok,
            content={
                "external_ids": {"auth_provider": "prov", "wrong_external_id": "id"}
            },
        )
        self.assertEqual(400, channel.code, msg=channel.json_body)
        self.assertEqual(Codes.MISSING_PARAM, channel.json_body["errcode"])

        channel = self.make_request(
            "PUT",
            self.url_other_user,
            access_token=self.admin_user_tok,
            content={"external_ids": {"external_id": "id"}},
        )
        self.assertEqual(400, channel.code, msg=channel.json_body)
        self.assertEqual(Codes.MISSING_PARAM, channel.json_body["errcode"])

        # threepids not valid
        channel = self.make_request(
            "PUT",
            self.url_other_user,
            access_token=self.admin_user_tok,
            content={"threepids": {"medium": "email", "wrong_address": "id"}},
        )
        self.assertEqual(400, channel.code, msg=channel.json_body)
        self.assertEqual(Codes.MISSING_PARAM, channel.json_body["errcode"])

        channel = self.make_request(
            "PUT",
            self.url_other_user,
            access_token=self.admin_user_tok,
            content={"threepids": {"address": "value"}},
        )
        self.assertEqual(400, channel.code, msg=channel.json_body)
        self.assertEqual(Codes.MISSING_PARAM, channel.json_body["errcode"])

    def test_get_user(self) -> None:
        """
        Test a simple get of a user.
        """
        channel = self.make_request(
            "GET",
            self.url_other_user,
            access_token=self.admin_user_tok,
        )

        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual("@user:test", channel.json_body["name"])
        self.assertEqual("User", channel.json_body["displayname"])
        self._check_fields(channel.json_body)

    def test_create_server_admin(self) -> None:
        """
        Check that a new admin user is created successfully.
        """
        url = self.url_prefix % "@bob:test"

        # Create user (server admin)
        body = {
            "password": "abc123",
            "admin": True,
            "displayname": "Bob's name",
            "threepids": [{"medium": "email", "address": "bob@bob.bob"}],
            "avatar_url": "mxc://fibble/wibble",
        }

        channel = self.make_request(
            "PUT",
            url,
            access_token=self.admin_user_tok,
            content=body,
        )

        self.assertEqual(201, channel.code, msg=channel.json_body)
        self.assertEqual("@bob:test", channel.json_body["name"])
        self.assertEqual("Bob's name", channel.json_body["displayname"])
        self.assertEqual("email", channel.json_body["threepids"][0]["medium"])
        self.assertEqual("bob@bob.bob", channel.json_body["threepids"][0]["address"])
        self.assertTrue(channel.json_body["admin"])
        self.assertEqual("mxc://fibble/wibble", channel.json_body["avatar_url"])
        self._check_fields(channel.json_body)

        # Get user
        channel = self.make_request(
            "GET",
            url,
            access_token=self.admin_user_tok,
        )

        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual("@bob:test", channel.json_body["name"])
        self.assertEqual("Bob's name", channel.json_body["displayname"])
        self.assertEqual("email", channel.json_body["threepids"][0]["medium"])
        self.assertEqual("bob@bob.bob", channel.json_body["threepids"][0]["address"])
        self.assertTrue(channel.json_body["admin"])
        self.assertFalse(channel.json_body["is_guest"])
        self.assertFalse(channel.json_body["deactivated"])
        self.assertEqual("mxc://fibble/wibble", channel.json_body["avatar_url"])
        self._check_fields(channel.json_body)

    def test_create_user(self) -> None:
        """
        Check that a new regular user is created successfully.
        """
        url = self.url_prefix % "@bob:test"

        # Create user
        body = {
            "password": "abc123",
            "admin": False,
            "displayname": "Bob's name",
            "threepids": [{"medium": "email", "address": "bob@bob.bob"}],
            "external_ids": [
                {
                    "external_id": "external_id1",
                    "auth_provider": "auth_provider1",
                },
            ],
            "avatar_url": "mxc://fibble/wibble",
        }

        channel = self.make_request(
            "PUT",
            url,
            access_token=self.admin_user_tok,
            content=body,
        )

        self.assertEqual(201, channel.code, msg=channel.json_body)
        self.assertEqual("@bob:test", channel.json_body["name"])
        self.assertEqual("Bob's name", channel.json_body["displayname"])
        self.assertEqual("email", channel.json_body["threepids"][0]["medium"])
        self.assertEqual("bob@bob.bob", channel.json_body["threepids"][0]["address"])
        self.assertEqual(1, len(channel.json_body["threepids"]))
        self.assertEqual(
            "external_id1", channel.json_body["external_ids"][0]["external_id"]
        )
        self.assertEqual(
            "auth_provider1", channel.json_body["external_ids"][0]["auth_provider"]
        )
        self.assertEqual(1, len(channel.json_body["external_ids"]))
        self.assertFalse(channel.json_body["admin"])
        self.assertEqual("mxc://fibble/wibble", channel.json_body["avatar_url"])
        self._check_fields(channel.json_body)

        # Get user
        channel = self.make_request(
            "GET",
            url,
            access_token=self.admin_user_tok,
        )

        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual("@bob:test", channel.json_body["name"])
        self.assertEqual("Bob's name", channel.json_body["displayname"])
        self.assertEqual("email", channel.json_body["threepids"][0]["medium"])
        self.assertEqual("bob@bob.bob", channel.json_body["threepids"][0]["address"])
        self.assertFalse(channel.json_body["admin"])
        self.assertFalse(channel.json_body["is_guest"])
        self.assertFalse(channel.json_body["deactivated"])
        self.assertFalse(channel.json_body["shadow_banned"])
        self.assertEqual("mxc://fibble/wibble", channel.json_body["avatar_url"])
        self._check_fields(channel.json_body)

    @override_config(
        {"limit_usage_by_mau": True, "max_mau_value": 2, "mau_trial_days": 0}
    )
    def test_create_user_mau_limit_reached_active_admin(self) -> None:
        """
        Check that an admin can register a new user via the admin API
        even if the MAU limit is reached.
        Admin user was active before creating user.
        """

        handler = self.hs.get_registration_handler()

        # Sync to set admin user to active
        # before limit of monthly active users is reached
        channel = self.make_request("GET", "/sync", access_token=self.admin_user_tok)

        if channel.code != 200:
            raise HttpResponseException(
                channel.code, channel.result["reason"], channel.result["body"]
            )

        # Set monthly active users to the limit
        self.store.get_monthly_active_count = Mock(
            return_value=make_awaitable(self.hs.config.server.max_mau_value)
        )
        # Check that the blocking of monthly active users is working as expected
        # The registration of a new user fails due to the limit
        self.get_failure(
            handler.register_user(localpart="local_part"), ResourceLimitError
        )

        # Register new user with admin API
        url = self.url_prefix % "@bob:test"

        # Create user
        channel = self.make_request(
            "PUT",
            url,
            access_token=self.admin_user_tok,
            content={"password": "abc123", "admin": False},
        )

        self.assertEqual(201, channel.code, msg=channel.json_body)
        self.assertEqual("@bob:test", channel.json_body["name"])
        self.assertFalse(channel.json_body["admin"])

    @override_config(
        {"limit_usage_by_mau": True, "max_mau_value": 2, "mau_trial_days": 0}
    )
    def test_create_user_mau_limit_reached_passive_admin(self) -> None:
        """
        Check that an admin can register a new user via the admin API
        even if the MAU limit is reached.
        Admin user was not active before creating user.
        """

        handler = self.hs.get_registration_handler()

        # Set monthly active users to the limit
        self.store.get_monthly_active_count = Mock(
            return_value=make_awaitable(self.hs.config.server.max_mau_value)
        )
        # Check that the blocking of monthly active users is working as expected
        # The registration of a new user fails due to the limit
        self.get_failure(
            handler.register_user(localpart="local_part"), ResourceLimitError
        )

        # Register new user with admin API
        url = self.url_prefix % "@bob:test"

        # Create user
        channel = self.make_request(
            "PUT",
            url,
            access_token=self.admin_user_tok,
            content={"password": "abc123", "admin": False},
        )

        # Admin user is not blocked by mau anymore
        self.assertEqual(201, channel.code, msg=channel.json_body)
        self.assertEqual("@bob:test", channel.json_body["name"])
        self.assertFalse(channel.json_body["admin"])

    @override_config(
        {
            "email": {
                "enable_notifs": True,
                "notif_for_new_users": True,
                "notif_from": "test@example.com",
            },
            "public_baseurl": "https://example.com",
        }
    )
    def test_create_user_email_notif_for_new_users(self) -> None:
        """
        Check that a new regular user is created successfully and
        got an email pusher.
        """
        url = self.url_prefix % "@bob:test"

        # Create user
        body = {
            "password": "abc123",
            # Note that the given email is not in canonical form.
            "threepids": [{"medium": "email", "address": "Bob@bob.bob"}],
        }

        channel = self.make_request(
            "PUT",
            url,
            access_token=self.admin_user_tok,
            content=body,
        )

        self.assertEqual(201, channel.code, msg=channel.json_body)
        self.assertEqual("@bob:test", channel.json_body["name"])
        self.assertEqual("email", channel.json_body["threepids"][0]["medium"])
        self.assertEqual("bob@bob.bob", channel.json_body["threepids"][0]["address"])

        pushers = list(
            self.get_success(self.store.get_pushers_by({"user_name": "@bob:test"}))
        )
        self.assertEqual(len(pushers), 1)
        self.assertEqual("@bob:test", pushers[0].user_name)

    @override_config(
        {
            "email": {
                "enable_notifs": False,
                "notif_for_new_users": False,
                "notif_from": "test@example.com",
            },
            "public_baseurl": "https://example.com",
        }
    )
    def test_create_user_email_no_notif_for_new_users(self) -> None:
        """
        Check that a new regular user is created successfully and
        got not an email pusher.
        """
        url = self.url_prefix % "@bob:test"

        # Create user
        body = {
            "password": "abc123",
            "threepids": [{"medium": "email", "address": "bob@bob.bob"}],
        }

        channel = self.make_request(
            "PUT",
            url,
            access_token=self.admin_user_tok,
            content=body,
        )

        self.assertEqual(201, channel.code, msg=channel.json_body)
        self.assertEqual("@bob:test", channel.json_body["name"])
        self.assertEqual("email", channel.json_body["threepids"][0]["medium"])
        self.assertEqual("bob@bob.bob", channel.json_body["threepids"][0]["address"])

        pushers = list(
            self.get_success(self.store.get_pushers_by({"user_name": "@bob:test"}))
        )
        self.assertEqual(len(pushers), 0)

    @override_config(
        {
            "email": {
                "enable_notifs": True,
                "notif_for_new_users": True,
                "notif_from": "test@example.com",
            },
            "public_baseurl": "https://example.com",
        }
    )
    def test_create_user_email_notif_for_new_users_with_msisdn_threepid(self) -> None:
        """
        Check that a new regular user is created successfully when they have a msisdn
        threepid and email notif_for_new_users is set to True.
        """
        url = self.url_prefix % "@bob:test"

        # Create user
        body = {
            "password": "abc123",
            "threepids": [{"medium": "msisdn", "address": "1234567890"}],
        }

        channel = self.make_request(
            "PUT",
            url,
            access_token=self.admin_user_tok,
            content=body,
        )

        self.assertEqual(201, channel.code, msg=channel.json_body)
        self.assertEqual("@bob:test", channel.json_body["name"])
        self.assertEqual("msisdn", channel.json_body["threepids"][0]["medium"])
        self.assertEqual("1234567890", channel.json_body["threepids"][0]["address"])

    def test_set_password(self) -> None:
        """
        Test setting a new password for another user.
        """

        # Change password
        channel = self.make_request(
            "PUT",
            self.url_other_user,
            access_token=self.admin_user_tok,
            content={"password": "hahaha"},
        )

        self.assertEqual(200, channel.code, msg=channel.json_body)
        self._check_fields(channel.json_body)

    def test_set_displayname(self) -> None:
        """
        Test setting the displayname of another user.
        """

        # Modify user
        channel = self.make_request(
            "PUT",
            self.url_other_user,
            access_token=self.admin_user_tok,
            content={"displayname": "foobar"},
        )

        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual("@user:test", channel.json_body["name"])
        self.assertEqual("foobar", channel.json_body["displayname"])

        # Get user
        channel = self.make_request(
            "GET",
            self.url_other_user,
            access_token=self.admin_user_tok,
        )

        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual("@user:test", channel.json_body["name"])
        self.assertEqual("foobar", channel.json_body["displayname"])

    def test_set_threepid(self) -> None:
        """
        Test setting threepid for an other user.
        """

        # Add two threepids to user
        channel = self.make_request(
            "PUT",
            self.url_other_user,
            access_token=self.admin_user_tok,
            content={
                "threepids": [
                    {"medium": "email", "address": "bob1@bob.bob"},
                    {"medium": "email", "address": "bob2@bob.bob"},
                ],
            },
        )

        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual("@user:test", channel.json_body["name"])
        self.assertEqual(2, len(channel.json_body["threepids"]))
        # result does not always have the same sort order, therefore it becomes sorted
        sorted_result = sorted(
            channel.json_body["threepids"], key=lambda k: k["address"]
        )
        self.assertEqual("email", sorted_result[0]["medium"])
        self.assertEqual("bob1@bob.bob", sorted_result[0]["address"])
        self.assertEqual("email", sorted_result[1]["medium"])
        self.assertEqual("bob2@bob.bob", sorted_result[1]["address"])
        self._check_fields(channel.json_body)

        # Set a new and remove a threepid
        channel = self.make_request(
            "PUT",
            self.url_other_user,
            access_token=self.admin_user_tok,
            content={
                "threepids": [
                    {"medium": "email", "address": "bob2@bob.bob"},
                    {"medium": "email", "address": "bob3@bob.bob"},
                ],
            },
        )

        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual("@user:test", channel.json_body["name"])
        self.assertEqual(2, len(channel.json_body["threepids"]))
        self.assertEqual("email", channel.json_body["threepids"][0]["medium"])
        self.assertEqual("bob2@bob.bob", channel.json_body["threepids"][0]["address"])
        self.assertEqual("email", channel.json_body["threepids"][1]["medium"])
        self.assertEqual("bob3@bob.bob", channel.json_body["threepids"][1]["address"])
        self._check_fields(channel.json_body)

        # Get user
        channel = self.make_request(
            "GET",
            self.url_other_user,
            access_token=self.admin_user_tok,
        )

        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual("@user:test", channel.json_body["name"])
        self.assertEqual(2, len(channel.json_body["threepids"]))
        self.assertEqual("email", channel.json_body["threepids"][0]["medium"])
        self.assertEqual("bob2@bob.bob", channel.json_body["threepids"][0]["address"])
        self.assertEqual("email", channel.json_body["threepids"][1]["medium"])
        self.assertEqual("bob3@bob.bob", channel.json_body["threepids"][1]["address"])
        self._check_fields(channel.json_body)

        # Remove threepids
        channel = self.make_request(
            "PUT",
            self.url_other_user,
            access_token=self.admin_user_tok,
            content={"threepids": []},
        )
        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual("@user:test", channel.json_body["name"])
        self.assertEqual(0, len(channel.json_body["threepids"]))
        self._check_fields(channel.json_body)

    def test_set_duplicate_threepid(self) -> None:
        """
        Test setting the same threepid for a second user.
        First user loses and second user gets mapping of this threepid.
        """

        # create a user to set a threepid
        first_user = self.register_user("first_user", "pass")
        url_first_user = self.url_prefix % first_user

        # Add threepid to first user
        channel = self.make_request(
            "PUT",
            url_first_user,
            access_token=self.admin_user_tok,
            content={
                "threepids": [
                    {"medium": "email", "address": "bob1@bob.bob"},
                ],
            },
        )

        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual(first_user, channel.json_body["name"])
        self.assertEqual(1, len(channel.json_body["threepids"]))
        self.assertEqual("email", channel.json_body["threepids"][0]["medium"])
        self.assertEqual("bob1@bob.bob", channel.json_body["threepids"][0]["address"])
        self._check_fields(channel.json_body)

        # Add threepids to other user
        channel = self.make_request(
            "PUT",
            self.url_other_user,
            access_token=self.admin_user_tok,
            content={
                "threepids": [
                    {"medium": "email", "address": "bob2@bob.bob"},
                ],
            },
        )

        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual("@user:test", channel.json_body["name"])
        self.assertEqual(1, len(channel.json_body["threepids"]))
        self.assertEqual("email", channel.json_body["threepids"][0]["medium"])
        self.assertEqual("bob2@bob.bob", channel.json_body["threepids"][0]["address"])
        self._check_fields(channel.json_body)

        # Add two new threepids to other user
        # one is used by first_user
        channel = self.make_request(
            "PUT",
            self.url_other_user,
            access_token=self.admin_user_tok,
            content={
                "threepids": [
                    {"medium": "email", "address": "bob1@bob.bob"},
                    {"medium": "email", "address": "bob3@bob.bob"},
                ],
            },
        )

        # other user has this two threepids
        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual("@user:test", channel.json_body["name"])
        self.assertEqual(2, len(channel.json_body["threepids"]))
        # result does not always have the same sort order, therefore it becomes sorted
        sorted_result = sorted(
            channel.json_body["threepids"], key=lambda k: k["address"]
        )
        self.assertEqual("email", sorted_result[0]["medium"])
        self.assertEqual("bob1@bob.bob", sorted_result[0]["address"])
        self.assertEqual("email", sorted_result[1]["medium"])
        self.assertEqual("bob3@bob.bob", sorted_result[1]["address"])
        self._check_fields(channel.json_body)

        # first_user has no threepid anymore
        channel = self.make_request(
            "GET",
            url_first_user,
            access_token=self.admin_user_tok,
        )
        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual(first_user, channel.json_body["name"])
        self.assertEqual(0, len(channel.json_body["threepids"]))
        self._check_fields(channel.json_body)

    def test_set_external_id(self) -> None:
        """
        Test setting external id for an other user.
        """

        # Add two external_ids
        channel = self.make_request(
            "PUT",
            self.url_other_user,
            access_token=self.admin_user_tok,
            content={
                "external_ids": [
                    {
                        "external_id": "external_id1",
                        "auth_provider": "auth_provider1",
                    },
                    {
                        "external_id": "external_id2",
                        "auth_provider": "auth_provider2",
                    },
                ]
            },
        )

        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual("@user:test", channel.json_body["name"])
        self.assertEqual(2, len(channel.json_body["external_ids"]))
        # result does not always have the same sort order, therefore it becomes sorted
        self.assertEqual(
            sorted(channel.json_body["external_ids"], key=lambda k: k["auth_provider"]),
            [
                {"auth_provider": "auth_provider1", "external_id": "external_id1"},
                {"auth_provider": "auth_provider2", "external_id": "external_id2"},
            ],
        )
        self._check_fields(channel.json_body)

        # Set a new and remove an external_id
        channel = self.make_request(
            "PUT",
            self.url_other_user,
            access_token=self.admin_user_tok,
            content={
                "external_ids": [
                    {
                        "external_id": "external_id2",
                        "auth_provider": "auth_provider2",
                    },
                    {
                        "external_id": "external_id3",
                        "auth_provider": "auth_provider3",
                    },
                ]
            },
        )

        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual("@user:test", channel.json_body["name"])
        self.assertEqual(2, len(channel.json_body["external_ids"]))
        self.assertEqual(
            channel.json_body["external_ids"],
            [
                {"auth_provider": "auth_provider2", "external_id": "external_id2"},
                {"auth_provider": "auth_provider3", "external_id": "external_id3"},
            ],
        )
        self._check_fields(channel.json_body)

        # Get user
        channel = self.make_request(
            "GET",
            self.url_other_user,
            access_token=self.admin_user_tok,
        )

        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual("@user:test", channel.json_body["name"])
        self.assertEqual(2, len(channel.json_body["external_ids"]))
        self.assertEqual(
            channel.json_body["external_ids"],
            [
                {"auth_provider": "auth_provider2", "external_id": "external_id2"},
                {"auth_provider": "auth_provider3", "external_id": "external_id3"},
            ],
        )
        self._check_fields(channel.json_body)

        # Remove external_ids
        channel = self.make_request(
            "PUT",
            self.url_other_user,
            access_token=self.admin_user_tok,
            content={"external_ids": []},
        )
        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual("@user:test", channel.json_body["name"])
        self.assertEqual(0, len(channel.json_body["external_ids"]))

    def test_set_duplicate_external_id(self) -> None:
        """
        Test that setting the same external id for a second user fails and
        external id from user must not be changed.
        """

        # create a user to use an external id
        first_user = self.register_user("first_user", "pass")
        url_first_user = self.url_prefix % first_user

        # Add an external id to first user
        channel = self.make_request(
            "PUT",
            url_first_user,
            access_token=self.admin_user_tok,
            content={
                "external_ids": [
                    {
                        "external_id": "external_id1",
                        "auth_provider": "auth_provider",
                    },
                ],
            },
        )

        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual(first_user, channel.json_body["name"])
        self.assertEqual(1, len(channel.json_body["external_ids"]))
        self.assertEqual(
            "external_id1", channel.json_body["external_ids"][0]["external_id"]
        )
        self.assertEqual(
            "auth_provider", channel.json_body["external_ids"][0]["auth_provider"]
        )
        self._check_fields(channel.json_body)

        # Add an external id to other user
        channel = self.make_request(
            "PUT",
            self.url_other_user,
            access_token=self.admin_user_tok,
            content={
                "external_ids": [
                    {
                        "external_id": "external_id2",
                        "auth_provider": "auth_provider",
                    },
                ],
            },
        )

        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual("@user:test", channel.json_body["name"])
        self.assertEqual(1, len(channel.json_body["external_ids"]))
        self.assertEqual(
            "external_id2", channel.json_body["external_ids"][0]["external_id"]
        )
        self.assertEqual(
            "auth_provider", channel.json_body["external_ids"][0]["auth_provider"]
        )
        self._check_fields(channel.json_body)

        # Add two new external_ids to other user
        # one is used by first
        channel = self.make_request(
            "PUT",
            self.url_other_user,
            access_token=self.admin_user_tok,
            content={
                "external_ids": [
                    {
                        "external_id": "external_id1",
                        "auth_provider": "auth_provider",
                    },
                    {
                        "external_id": "external_id3",
                        "auth_provider": "auth_provider",
                    },
                ],
            },
        )

        # must fail
        self.assertEqual(409, channel.code, msg=channel.json_body)
        self.assertEqual(Codes.UNKNOWN, channel.json_body["errcode"])
        self.assertEqual("External id is already in use.", channel.json_body["error"])

        # other user must not changed
        channel = self.make_request(
            "GET",
            self.url_other_user,
            access_token=self.admin_user_tok,
        )

        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual("@user:test", channel.json_body["name"])
        self.assertEqual(1, len(channel.json_body["external_ids"]))
        self.assertEqual(
            "external_id2", channel.json_body["external_ids"][0]["external_id"]
        )
        self.assertEqual(
            "auth_provider", channel.json_body["external_ids"][0]["auth_provider"]
        )
        self._check_fields(channel.json_body)

        # first user must not changed
        channel = self.make_request(
            "GET",
            url_first_user,
            access_token=self.admin_user_tok,
        )

        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual(first_user, channel.json_body["name"])
        self.assertEqual(1, len(channel.json_body["external_ids"]))
        self.assertEqual(
            "external_id1", channel.json_body["external_ids"][0]["external_id"]
        )
        self.assertEqual(
            "auth_provider", channel.json_body["external_ids"][0]["auth_provider"]
        )
        self._check_fields(channel.json_body)

    def test_deactivate_user(self) -> None:
        """
        Test deactivating another user.
        """

        # set attributes for user
        self.get_success(
            self.store.set_profile_avatar_url("user", "mxc://servername/mediaid")
        )
        self.get_success(
            self.store.user_add_threepid("@user:test", "email", "foo@bar.com", 0, 0)
        )

        # Get user
        channel = self.make_request(
            "GET",
            self.url_other_user,
            access_token=self.admin_user_tok,
        )

        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual("@user:test", channel.json_body["name"])
        self.assertFalse(channel.json_body["deactivated"])
        self.assertEqual("foo@bar.com", channel.json_body["threepids"][0]["address"])
        self.assertEqual("mxc://servername/mediaid", channel.json_body["avatar_url"])
        self.assertEqual("User", channel.json_body["displayname"])

        # Deactivate user
        channel = self.make_request(
            "PUT",
            self.url_other_user,
            access_token=self.admin_user_tok,
            content={"deactivated": True},
        )

        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual("@user:test", channel.json_body["name"])
        self.assertTrue(channel.json_body["deactivated"])
        self.assertEqual(0, len(channel.json_body["threepids"]))
        self.assertEqual("mxc://servername/mediaid", channel.json_body["avatar_url"])
        self.assertEqual("User", channel.json_body["displayname"])

        # This key was removed intentionally. Ensure it is not accidentally re-included.
        self.assertNotIn("password_hash", channel.json_body)

        # the user is deactivated, the threepid will be deleted

        # Get user
        channel = self.make_request(
            "GET",
            self.url_other_user,
            access_token=self.admin_user_tok,
        )

        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual("@user:test", channel.json_body["name"])
        self.assertTrue(channel.json_body["deactivated"])
        self.assertEqual(0, len(channel.json_body["threepids"]))
        self.assertEqual("mxc://servername/mediaid", channel.json_body["avatar_url"])
        self.assertEqual("User", channel.json_body["displayname"])

        # This key was removed intentionally. Ensure it is not accidentally re-included.
        self.assertNotIn("password_hash", channel.json_body)

    @override_config({"user_directory": {"enabled": True, "search_all_users": True}})
    def test_change_name_deactivate_user_user_directory(self) -> None:
        """
        Test change profile information of a deactivated user and
        check that it does not appear in user directory
        """

        # is in user directory
        profile = self.get_success(self.store.get_user_in_directory(self.other_user))
        assert profile is not None
        self.assertTrue(profile["display_name"] == "User")

        # Deactivate user
        channel = self.make_request(
            "PUT",
            self.url_other_user,
            access_token=self.admin_user_tok,
            content={"deactivated": True},
        )

        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual("@user:test", channel.json_body["name"])
        self.assertTrue(channel.json_body["deactivated"])

        # is not in user directory
        profile = self.get_success(self.store.get_user_in_directory(self.other_user))
        self.assertIsNone(profile)

        # Set new displayname user
        channel = self.make_request(
            "PUT",
            self.url_other_user,
            access_token=self.admin_user_tok,
            content={"displayname": "Foobar"},
        )

        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual("@user:test", channel.json_body["name"])
        self.assertTrue(channel.json_body["deactivated"])
        self.assertEqual("Foobar", channel.json_body["displayname"])

        # is not in user directory
        profile = self.get_success(self.store.get_user_in_directory(self.other_user))
        self.assertIsNone(profile)

    def test_reactivate_user(self) -> None:
        """
        Test reactivating another user.
        """

        # Deactivate the user.
        self._deactivate_user("@user:test")

        # Attempt to reactivate the user (without a password).
        channel = self.make_request(
            "PUT",
            self.url_other_user,
            access_token=self.admin_user_tok,
            content={"deactivated": False},
        )
        self.assertEqual(400, channel.code, msg=channel.json_body)

        # Reactivate the user.
        channel = self.make_request(
            "PUT",
            self.url_other_user,
            access_token=self.admin_user_tok,
            content={"deactivated": False, "password": "foo"},
        )
        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual("@user:test", channel.json_body["name"])
        self.assertFalse(channel.json_body["deactivated"])
        self._is_erased("@user:test", False)

        # This key was removed intentionally. Ensure it is not accidentally re-included.
        self.assertNotIn("password_hash", channel.json_body)

    @override_config({"password_config": {"localdb_enabled": False}})
    def test_reactivate_user_localdb_disabled(self) -> None:
        """
        Test reactivating another user when using SSO.
        """

        # Deactivate the user.
        self._deactivate_user("@user:test")

        # Reactivate the user with a password
        channel = self.make_request(
            "PUT",
            self.url_other_user,
            access_token=self.admin_user_tok,
            content={"deactivated": False, "password": "foo"},
        )
        self.assertEqual(403, channel.code, msg=channel.json_body)
        self.assertEqual(Codes.FORBIDDEN, channel.json_body["errcode"])

        # Reactivate the user without a password.
        channel = self.make_request(
            "PUT",
            self.url_other_user,
            access_token=self.admin_user_tok,
            content={"deactivated": False},
        )
        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual("@user:test", channel.json_body["name"])
        self.assertFalse(channel.json_body["deactivated"])
        self._is_erased("@user:test", False)

        # This key was removed intentionally. Ensure it is not accidentally re-included.
        self.assertNotIn("password_hash", channel.json_body)

    @override_config({"password_config": {"enabled": False}})
    def test_reactivate_user_password_disabled(self) -> None:
        """
        Test reactivating another user when using SSO.
        """

        # Deactivate the user.
        self._deactivate_user("@user:test")

        # Reactivate the user with a password
        channel = self.make_request(
            "PUT",
            self.url_other_user,
            access_token=self.admin_user_tok,
            content={"deactivated": False, "password": "foo"},
        )
        self.assertEqual(403, channel.code, msg=channel.json_body)
        self.assertEqual(Codes.FORBIDDEN, channel.json_body["errcode"])

        # Reactivate the user without a password.
        channel = self.make_request(
            "PUT",
            self.url_other_user,
            access_token=self.admin_user_tok,
            content={"deactivated": False},
        )
        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual("@user:test", channel.json_body["name"])
        self.assertFalse(channel.json_body["deactivated"])
        self._is_erased("@user:test", False)

        # This key was removed intentionally. Ensure it is not accidentally re-included.
        self.assertNotIn("password_hash", channel.json_body)

    def test_set_user_as_admin(self) -> None:
        """
        Test setting the admin flag on a user.
        """

        # Set a user as an admin
        channel = self.make_request(
            "PUT",
            self.url_other_user,
            access_token=self.admin_user_tok,
            content={"admin": True},
        )

        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual("@user:test", channel.json_body["name"])
        self.assertTrue(channel.json_body["admin"])

        # Get user
        channel = self.make_request(
            "GET",
            self.url_other_user,
            access_token=self.admin_user_tok,
        )

        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual("@user:test", channel.json_body["name"])
        self.assertTrue(channel.json_body["admin"])

    def test_set_user_type(self) -> None:
        """
        Test changing user type.
        """

        # Set to support type
        channel = self.make_request(
            "PUT",
            self.url_other_user,
            access_token=self.admin_user_tok,
            content={"user_type": UserTypes.SUPPORT},
        )

        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual("@user:test", channel.json_body["name"])
        self.assertEqual(UserTypes.SUPPORT, channel.json_body["user_type"])

        # Get user
        channel = self.make_request(
            "GET",
            self.url_other_user,
            access_token=self.admin_user_tok,
        )

        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual("@user:test", channel.json_body["name"])
        self.assertEqual(UserTypes.SUPPORT, channel.json_body["user_type"])

        # Change back to a regular user
        channel = self.make_request(
            "PUT",
            self.url_other_user,
            access_token=self.admin_user_tok,
            content={"user_type": None},
        )

        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual("@user:test", channel.json_body["name"])
        self.assertIsNone(channel.json_body["user_type"])

        # Get user
        channel = self.make_request(
            "GET",
            self.url_other_user,
            access_token=self.admin_user_tok,
        )

        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual("@user:test", channel.json_body["name"])
        self.assertIsNone(channel.json_body["user_type"])

    def test_accidental_deactivation_prevention(self) -> None:
        """
        Ensure an account can't accidentally be deactivated by using a str value
        for the deactivated body parameter
        """
        url = self.url_prefix % "@bob:test"

        # Create user
        channel = self.make_request(
            "PUT",
            url,
            access_token=self.admin_user_tok,
            content={"password": "abc123"},
        )

        self.assertEqual(201, channel.code, msg=channel.json_body)
        self.assertEqual("@bob:test", channel.json_body["name"])
        self.assertEqual("bob", channel.json_body["displayname"])

        # Get user
        channel = self.make_request(
            "GET",
            url,
            access_token=self.admin_user_tok,
        )

        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual("@bob:test", channel.json_body["name"])
        self.assertEqual("bob", channel.json_body["displayname"])
        self.assertEqual(0, channel.json_body["deactivated"])

        # Change password (and use a str for deactivate instead of a bool)
        channel = self.make_request(
            "PUT",
            url,
            access_token=self.admin_user_tok,
            content={"password": "abc123", "deactivated": "false"},
        )

        self.assertEqual(400, channel.code, msg=channel.json_body)

        # Check user is not deactivated
        channel = self.make_request(
            "GET",
            url,
            access_token=self.admin_user_tok,
        )

        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual("@bob:test", channel.json_body["name"])
        self.assertEqual("bob", channel.json_body["displayname"])

        # Ensure they're still alive
        self.assertEqual(0, channel.json_body["deactivated"])

    @override_config(
        {
            "experimental_features": {
                "msc3866": {
                    "enabled": True,
                    "require_approval_for_new_accounts": True,
                }
            }
        }
    )
    def test_approve_account(self) -> None:
        """Tests that approving an account correctly sets the approved flag for the user."""
        url = self.url_prefix % "@bob:test"

        # Create the user using the client-server API since otherwise the user will be
        # marked as approved automatically.
        channel = self.make_request(
            "POST",
            "register",
            {
                "username": "bob",
                "password": "test",
                "auth": {"type": LoginType.DUMMY},
            },
        )
        self.assertEqual(403, channel.code, channel.result)
        self.assertEqual(Codes.USER_AWAITING_APPROVAL, channel.json_body["errcode"])
        self.assertEqual(
            ApprovalNoticeMedium.NONE, channel.json_body["approval_notice_medium"]
        )

        # Get user
        channel = self.make_request(
            "GET",
            url,
            access_token=self.admin_user_tok,
        )

        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertIs(False, channel.json_body["approved"])

        # Approve user
        channel = self.make_request(
            "PUT",
            url,
            access_token=self.admin_user_tok,
            content={"approved": True},
        )

        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertIs(True, channel.json_body["approved"])

        # Check that the user is now approved
        channel = self.make_request(
            "GET",
            url,
            access_token=self.admin_user_tok,
        )

        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertIs(True, channel.json_body["approved"])

    @override_config(
        {
            "experimental_features": {
                "msc3866": {
                    "enabled": True,
                    "require_approval_for_new_accounts": True,
                }
            }
        }
    )
    def test_register_approved(self) -> None:
        url = self.url_prefix % "@bob:test"

        # Create user
        channel = self.make_request(
            "PUT",
            url,
            access_token=self.admin_user_tok,
            content={"password": "abc123", "approved": True},
        )

        self.assertEqual(201, channel.code, msg=channel.json_body)
        self.assertEqual("@bob:test", channel.json_body["name"])
        self.assertEqual(1, channel.json_body["approved"])

        # Get user
        channel = self.make_request(
            "GET",
            url,
            access_token=self.admin_user_tok,
        )

        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual("@bob:test", channel.json_body["name"])
        self.assertEqual(1, channel.json_body["approved"])

    def _is_erased(self, user_id: str, expect: bool) -> None:
        """Assert that the user is erased or not"""
        d = self.store.is_user_erased(user_id)
        if expect:
            self.assertTrue(self.get_success(d))
        else:
            self.assertFalse(self.get_success(d))

    def _deactivate_user(self, user_id: str) -> None:
        """Deactivate user and set as erased"""

        # Deactivate the user.
        channel = self.make_request(
            "PUT",
            self.url_prefix % urllib.parse.quote(user_id),
            access_token=self.admin_user_tok,
            content={"deactivated": True},
        )
        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertTrue(channel.json_body["deactivated"])
        self._is_erased(user_id, False)
        d = self.store.mark_user_erased(user_id)
        self.assertIsNone(self.get_success(d))
        self._is_erased(user_id, True)

        # This key was removed intentionally. Ensure it is not accidentally re-included.
        self.assertNotIn("password_hash", channel.json_body)

    def _check_fields(self, content: JsonDict) -> None:
        """Checks that the expected user attributes are present in content

        Args:
            content: Content dictionary to check
        """
        self.assertIn("displayname", content)
        self.assertIn("threepids", content)
        self.assertIn("avatar_url", content)
        self.assertIn("admin", content)
        self.assertIn("deactivated", content)
        self.assertIn("erased", content)
        self.assertIn("shadow_banned", content)
        self.assertIn("creation_ts", content)
        self.assertIn("appservice_id", content)
        self.assertIn("consent_server_notice_sent", content)
        self.assertIn("consent_version", content)
        self.assertIn("consent_ts", content)
        self.assertIn("external_ids", content)

        # This key was removed intentionally. Ensure it is not accidentally re-included.
        self.assertNotIn("password_hash", content)


class UserMembershipRestTestCase(unittest.HomeserverTestCase):

    servlets = [
        synapse.rest.admin.register_servlets,
        login.register_servlets,
        room.register_servlets,
    ]

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self.admin_user = self.register_user("admin", "pass", admin=True)
        self.admin_user_tok = self.login("admin", "pass")

        self.other_user = self.register_user("user", "pass")
        self.url = "/_synapse/admin/v1/users/%s/joined_rooms" % urllib.parse.quote(
            self.other_user
        )

    def test_no_auth(self) -> None:
        """
        Try to list rooms of an user without authentication.
        """
        channel = self.make_request("GET", self.url, b"{}")

        self.assertEqual(401, channel.code, msg=channel.json_body)
        self.assertEqual(Codes.MISSING_TOKEN, channel.json_body["errcode"])

    def test_requester_is_no_admin(self) -> None:
        """
        If the user is not a server admin, an error is returned.
        """
        other_user_token = self.login("user", "pass")

        channel = self.make_request(
            "GET",
            self.url,
            access_token=other_user_token,
        )

        self.assertEqual(403, channel.code, msg=channel.json_body)
        self.assertEqual(Codes.FORBIDDEN, channel.json_body["errcode"])

    def test_user_does_not_exist(self) -> None:
        """
        Tests that a lookup for a user that does not exist returns an empty list
        """
        url = "/_synapse/admin/v1/users/@unknown_person:test/joined_rooms"
        channel = self.make_request(
            "GET",
            url,
            access_token=self.admin_user_tok,
        )

        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual(0, channel.json_body["total"])
        self.assertEqual(0, len(channel.json_body["joined_rooms"]))

    def test_user_is_not_local(self) -> None:
        """
        Tests that a lookup for a user that is not a local and participates in no conversation returns an empty list
        """
        url = "/_synapse/admin/v1/users/@unknown_person:unknown_domain/joined_rooms"

        channel = self.make_request(
            "GET",
            url,
            access_token=self.admin_user_tok,
        )

        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual(0, channel.json_body["total"])
        self.assertEqual(0, len(channel.json_body["joined_rooms"]))

    def test_no_memberships(self) -> None:
        """
        Tests that a normal lookup for rooms is successfully
        if user has no memberships
        """
        # Get rooms
        channel = self.make_request(
            "GET",
            self.url,
            access_token=self.admin_user_tok,
        )

        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual(0, channel.json_body["total"])
        self.assertEqual(0, len(channel.json_body["joined_rooms"]))

    def test_get_rooms(self) -> None:
        """
        Tests that a normal lookup for rooms is successfully
        """
        # Create rooms and join
        other_user_tok = self.login("user", "pass")
        number_rooms = 5
        for _ in range(number_rooms):
            self.helper.create_room_as(self.other_user, tok=other_user_tok)

        # Get rooms
        channel = self.make_request(
            "GET",
            self.url,
            access_token=self.admin_user_tok,
        )

        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual(number_rooms, channel.json_body["total"])
        self.assertEqual(number_rooms, len(channel.json_body["joined_rooms"]))

    def test_get_rooms_with_nonlocal_user(self) -> None:
        """
        Tests that a normal lookup for rooms is successful with a non-local user
        """

        other_user_tok = self.login("user", "pass")
        event_builder_factory = self.hs.get_event_builder_factory()
        event_creation_handler = self.hs.get_event_creation_handler()
        storage_controllers = self.hs.get_storage_controllers()

        # Create two rooms, one with a local user only and one with both a local
        # and remote user.
        self.helper.create_room_as(self.other_user, tok=other_user_tok)
        local_and_remote_room_id = self.helper.create_room_as(
            self.other_user, tok=other_user_tok
        )

        # Add a remote user to the room.
        builder = event_builder_factory.for_room_version(
            RoomVersions.V1,
            {
                "type": "m.room.member",
                "sender": "@joiner:remote_hs",
                "state_key": "@joiner:remote_hs",
                "room_id": local_and_remote_room_id,
                "content": {"membership": "join"},
            },
        )

        event, context = self.get_success(
            event_creation_handler.create_new_client_event(builder)
        )

        self.get_success(storage_controllers.persistence.persist_event(event, context))

        # Now get rooms
        url = "/_synapse/admin/v1/users/@joiner:remote_hs/joined_rooms"
        channel = self.make_request(
            "GET",
            url,
            access_token=self.admin_user_tok,
        )

        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual(1, channel.json_body["total"])
        self.assertEqual([local_and_remote_room_id], channel.json_body["joined_rooms"])


class PushersRestTestCase(unittest.HomeserverTestCase):

    servlets = [
        synapse.rest.admin.register_servlets,
        login.register_servlets,
    ]

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self.store = hs.get_datastores().main

        self.admin_user = self.register_user("admin", "pass", admin=True)
        self.admin_user_tok = self.login("admin", "pass")

        self.other_user = self.register_user("user", "pass")
        self.url = "/_synapse/admin/v1/users/%s/pushers" % urllib.parse.quote(
            self.other_user
        )

    def test_no_auth(self) -> None:
        """
        Try to list pushers of an user without authentication.
        """
        channel = self.make_request("GET", self.url, b"{}")

        self.assertEqual(401, channel.code, msg=channel.json_body)
        self.assertEqual(Codes.MISSING_TOKEN, channel.json_body["errcode"])

    def test_requester_is_no_admin(self) -> None:
        """
        If the user is not a server admin, an error is returned.
        """
        other_user_token = self.login("user", "pass")

        channel = self.make_request(
            "GET",
            self.url,
            access_token=other_user_token,
        )

        self.assertEqual(403, channel.code, msg=channel.json_body)
        self.assertEqual(Codes.FORBIDDEN, channel.json_body["errcode"])

    def test_user_does_not_exist(self) -> None:
        """
        Tests that a lookup for a user that does not exist returns a 404
        """
        url = "/_synapse/admin/v1/users/@unknown_person:test/pushers"
        channel = self.make_request(
            "GET",
            url,
            access_token=self.admin_user_tok,
        )

        self.assertEqual(404, channel.code, msg=channel.json_body)
        self.assertEqual(Codes.NOT_FOUND, channel.json_body["errcode"])

    def test_user_is_not_local(self) -> None:
        """
        Tests that a lookup for a user that is not a local returns a 400
        """
        url = "/_synapse/admin/v1/users/@unknown_person:unknown_domain/pushers"

        channel = self.make_request(
            "GET",
            url,
            access_token=self.admin_user_tok,
        )

        self.assertEqual(400, channel.code, msg=channel.json_body)
        self.assertEqual("Can only look up local users", channel.json_body["error"])

    def test_get_pushers(self) -> None:
        """
        Tests that a normal lookup for pushers is successfully
        """

        # Get pushers
        channel = self.make_request(
            "GET",
            self.url,
            access_token=self.admin_user_tok,
        )

        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual(0, channel.json_body["total"])

        # Register the pusher
        other_user_token = self.login("user", "pass")
        user_tuple = self.get_success(
            self.store.get_user_by_access_token(other_user_token)
        )
        assert user_tuple is not None
        token_id = user_tuple.token_id

        self.get_success(
            self.hs.get_pusherpool().add_or_update_pusher(
                user_id=self.other_user,
                access_token=token_id,
                kind="http",
                app_id="m.http",
                app_display_name="HTTP Push Notifications",
                device_display_name="pushy push",
                pushkey="a@example.com",
                lang=None,
                data={"url": "https://example.com/_matrix/push/v1/notify"},
            )
        )

        # Get pushers
        channel = self.make_request(
            "GET",
            self.url,
            access_token=self.admin_user_tok,
        )

        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual(1, channel.json_body["total"])

        for p in channel.json_body["pushers"]:
            self.assertIn("pushkey", p)
            self.assertIn("kind", p)
            self.assertIn("app_id", p)
            self.assertIn("app_display_name", p)
            self.assertIn("device_display_name", p)
            self.assertIn("profile_tag", p)
            self.assertIn("lang", p)
            self.assertIn("url", p["data"])


class UserMediaRestTestCase(unittest.HomeserverTestCase):

    servlets = [
        synapse.rest.admin.register_servlets,
        login.register_servlets,
    ]

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self.store = hs.get_datastores().main
        self.media_repo = hs.get_media_repository_resource()
        self.filepaths = MediaFilePaths(hs.config.media.media_store_path)

        self.admin_user = self.register_user("admin", "pass", admin=True)
        self.admin_user_tok = self.login("admin", "pass")

        self.other_user = self.register_user("user", "pass")
        self.url = "/_synapse/admin/v1/users/%s/media" % urllib.parse.quote(
            self.other_user
        )

    @parameterized.expand(["GET", "DELETE"])
    def test_no_auth(self, method: str) -> None:
        """Try to list media of an user without authentication."""
        channel = self.make_request(method, self.url, {})

        self.assertEqual(401, channel.code, msg=channel.json_body)
        self.assertEqual(Codes.MISSING_TOKEN, channel.json_body["errcode"])

    @parameterized.expand(["GET", "DELETE"])
    def test_requester_is_no_admin(self, method: str) -> None:
        """If the user is not a server admin, an error is returned."""
        other_user_token = self.login("user", "pass")

        channel = self.make_request(
            method,
            self.url,
            access_token=other_user_token,
        )

        self.assertEqual(403, channel.code, msg=channel.json_body)
        self.assertEqual(Codes.FORBIDDEN, channel.json_body["errcode"])

    @parameterized.expand(["GET", "DELETE"])
    def test_user_does_not_exist(self, method: str) -> None:
        """Tests that a lookup for a user that does not exist returns a 404"""
        url = "/_synapse/admin/v1/users/@unknown_person:test/media"
        channel = self.make_request(
            method,
            url,
            access_token=self.admin_user_tok,
        )

        self.assertEqual(404, channel.code, msg=channel.json_body)
        self.assertEqual(Codes.NOT_FOUND, channel.json_body["errcode"])

    @parameterized.expand(["GET", "DELETE"])
    def test_user_is_not_local(self, method: str) -> None:
        """Tests that a lookup for a user that is not a local returns a 400"""
        url = "/_synapse/admin/v1/users/@unknown_person:unknown_domain/media"

        channel = self.make_request(
            method,
            url,
            access_token=self.admin_user_tok,
        )

        self.assertEqual(400, channel.code, msg=channel.json_body)
        self.assertEqual("Can only look up local users", channel.json_body["error"])

    def test_limit_GET(self) -> None:
        """Testing list of media with limit"""

        number_media = 20
        other_user_tok = self.login("user", "pass")
        self._create_media_for_user(other_user_tok, number_media)

        channel = self.make_request(
            "GET",
            self.url + "?limit=5",
            access_token=self.admin_user_tok,
        )

        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual(channel.json_body["total"], number_media)
        self.assertEqual(len(channel.json_body["media"]), 5)
        self.assertEqual(channel.json_body["next_token"], 5)
        self._check_fields(channel.json_body["media"])

    def test_limit_DELETE(self) -> None:
        """Testing delete of media with limit"""

        number_media = 20
        other_user_tok = self.login("user", "pass")
        self._create_media_for_user(other_user_tok, number_media)

        channel = self.make_request(
            "DELETE",
            self.url + "?limit=5",
            access_token=self.admin_user_tok,
        )

        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual(channel.json_body["total"], 5)
        self.assertEqual(len(channel.json_body["deleted_media"]), 5)

    def test_from_GET(self) -> None:
        """Testing list of media with a defined starting point (from)"""

        number_media = 20
        other_user_tok = self.login("user", "pass")
        self._create_media_for_user(other_user_tok, number_media)

        channel = self.make_request(
            "GET",
            self.url + "?from=5",
            access_token=self.admin_user_tok,
        )

        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual(channel.json_body["total"], number_media)
        self.assertEqual(len(channel.json_body["media"]), 15)
        self.assertNotIn("next_token", channel.json_body)
        self._check_fields(channel.json_body["media"])

    def test_from_DELETE(self) -> None:
        """Testing delete of media with a defined starting point (from)"""

        number_media = 20
        other_user_tok = self.login("user", "pass")
        self._create_media_for_user(other_user_tok, number_media)

        channel = self.make_request(
            "DELETE",
            self.url + "?from=5",
            access_token=self.admin_user_tok,
        )

        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual(channel.json_body["total"], 15)
        self.assertEqual(len(channel.json_body["deleted_media"]), 15)

    def test_limit_and_from_GET(self) -> None:
        """Testing list of media with a defined starting point and limit"""

        number_media = 20
        other_user_tok = self.login("user", "pass")
        self._create_media_for_user(other_user_tok, number_media)

        channel = self.make_request(
            "GET",
            self.url + "?from=5&limit=10",
            access_token=self.admin_user_tok,
        )

        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual(channel.json_body["total"], number_media)
        self.assertEqual(channel.json_body["next_token"], 15)
        self.assertEqual(len(channel.json_body["media"]), 10)
        self._check_fields(channel.json_body["media"])

    def test_limit_and_from_DELETE(self) -> None:
        """Testing delete of media with a defined starting point and limit"""

        number_media = 20
        other_user_tok = self.login("user", "pass")
        self._create_media_for_user(other_user_tok, number_media)

        channel = self.make_request(
            "DELETE",
            self.url + "?from=5&limit=10",
            access_token=self.admin_user_tok,
        )

        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual(channel.json_body["total"], 10)
        self.assertEqual(len(channel.json_body["deleted_media"]), 10)

    @parameterized.expand(["GET", "DELETE"])
    def test_invalid_parameter(self, method: str) -> None:
        """If parameters are invalid, an error is returned."""
        # unkown order_by
        channel = self.make_request(
            method,
            self.url + "?order_by=bar",
            access_token=self.admin_user_tok,
        )

        self.assertEqual(400, channel.code, msg=channel.json_body)
        self.assertEqual(Codes.INVALID_PARAM, channel.json_body["errcode"])

        # invalid search order
        channel = self.make_request(
            method,
            self.url + "?dir=bar",
            access_token=self.admin_user_tok,
        )

        self.assertEqual(400, channel.code, msg=channel.json_body)
        self.assertEqual(Codes.INVALID_PARAM, channel.json_body["errcode"])

        # negative limit
        channel = self.make_request(
            method,
            self.url + "?limit=-5",
            access_token=self.admin_user_tok,
        )

        self.assertEqual(400, channel.code, msg=channel.json_body)
        self.assertEqual(Codes.INVALID_PARAM, channel.json_body["errcode"])

        # negative from
        channel = self.make_request(
            method,
            self.url + "?from=-5",
            access_token=self.admin_user_tok,
        )

        self.assertEqual(400, channel.code, msg=channel.json_body)
        self.assertEqual(Codes.INVALID_PARAM, channel.json_body["errcode"])

    def test_next_token(self) -> None:
        """
        Testing that `next_token` appears at the right place

        For deleting media `next_token` is not useful, because
        after deleting media the media has a new order.
        """

        number_media = 20
        other_user_tok = self.login("user", "pass")
        self._create_media_for_user(other_user_tok, number_media)

        #  `next_token` does not appear
        # Number of results is the number of entries
        channel = self.make_request(
            "GET",
            self.url + "?limit=20",
            access_token=self.admin_user_tok,
        )

        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual(channel.json_body["total"], number_media)
        self.assertEqual(len(channel.json_body["media"]), number_media)
        self.assertNotIn("next_token", channel.json_body)

        #  `next_token` does not appear
        # Number of max results is larger than the number of entries
        channel = self.make_request(
            "GET",
            self.url + "?limit=21",
            access_token=self.admin_user_tok,
        )

        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual(channel.json_body["total"], number_media)
        self.assertEqual(len(channel.json_body["media"]), number_media)
        self.assertNotIn("next_token", channel.json_body)

        #  `next_token` does appear
        # Number of max results is smaller than the number of entries
        channel = self.make_request(
            "GET",
            self.url + "?limit=19",
            access_token=self.admin_user_tok,
        )

        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual(channel.json_body["total"], number_media)
        self.assertEqual(len(channel.json_body["media"]), 19)
        self.assertEqual(channel.json_body["next_token"], 19)

        # Check
        # Set `from` to value of `next_token` for request remaining entries
        #  `next_token` does not appear
        channel = self.make_request(
            "GET",
            self.url + "?from=19",
            access_token=self.admin_user_tok,
        )

        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual(channel.json_body["total"], number_media)
        self.assertEqual(len(channel.json_body["media"]), 1)
        self.assertNotIn("next_token", channel.json_body)

    def test_user_has_no_media_GET(self) -> None:
        """
        Tests that a normal lookup for media is successfully
        if user has no media created
        """

        channel = self.make_request(
            "GET",
            self.url,
            access_token=self.admin_user_tok,
        )

        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual(0, channel.json_body["total"])
        self.assertEqual(0, len(channel.json_body["media"]))

    def test_user_has_no_media_DELETE(self) -> None:
        """
        Tests that a delete is successful if user has no media
        """

        channel = self.make_request(
            "DELETE",
            self.url,
            access_token=self.admin_user_tok,
        )

        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual(0, channel.json_body["total"])
        self.assertEqual(0, len(channel.json_body["deleted_media"]))

    def test_get_media(self) -> None:
        """Tests that a normal lookup for media is successful"""

        number_media = 5
        other_user_tok = self.login("user", "pass")
        self._create_media_for_user(other_user_tok, number_media)

        channel = self.make_request(
            "GET",
            self.url,
            access_token=self.admin_user_tok,
        )

        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual(number_media, channel.json_body["total"])
        self.assertEqual(number_media, len(channel.json_body["media"]))
        self.assertNotIn("next_token", channel.json_body)
        self._check_fields(channel.json_body["media"])

    def test_delete_media(self) -> None:
        """Tests that a normal delete of media is successful"""

        number_media = 5
        other_user_tok = self.login("user", "pass")
        media_ids = self._create_media_for_user(other_user_tok, number_media)

        # Test if the file exists
        local_paths = []
        for media_id in media_ids:
            local_path = self.filepaths.local_media_filepath(media_id)
            self.assertTrue(os.path.exists(local_path))
            local_paths.append(local_path)

        channel = self.make_request(
            "DELETE",
            self.url,
            access_token=self.admin_user_tok,
        )

        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual(number_media, channel.json_body["total"])
        self.assertEqual(number_media, len(channel.json_body["deleted_media"]))
        self.assertCountEqual(channel.json_body["deleted_media"], media_ids)

        # Test if the file is deleted
        for local_path in local_paths:
            self.assertFalse(os.path.exists(local_path))

    def test_order_by(self) -> None:
        """
        Testing order list with parameter `order_by`
        """

        other_user_tok = self.login("user", "pass")

        # Resolution: 1×1, MIME type: image/png, Extension: png, Size: 67 B
        image_data1 = SMALL_PNG
        # Resolution: 1×1, MIME type: image/gif, Extension: gif, Size: 35 B
        image_data2 = unhexlify(
            b"47494638376101000100800100000000"
            b"ffffff2c00000000010001000002024c"
            b"01003b"
        )
        # Resolution: 1×1, MIME type: image/bmp, Extension: bmp, Size: 54 B
        image_data3 = unhexlify(
            b"424d3a0000000000000036000000280000000100000001000000"
            b"0100180000000000040000000000000000000000000000000000"
            b"0000"
        )

        # create media and make sure they do not have the same timestamp
        media1 = self._create_media_and_access(other_user_tok, image_data1, "image.png")
        self.pump(1.0)
        media2 = self._create_media_and_access(other_user_tok, image_data2, "image.gif")
        self.pump(1.0)
        media3 = self._create_media_and_access(other_user_tok, image_data3, "image.bmp")
        self.pump(1.0)

        # Mark one media as safe from quarantine.
        self.get_success(self.store.mark_local_media_as_safe(media2))
        # Quarantine one media
        self.get_success(
            self.store.quarantine_media_by_id("test", media3, self.admin_user)
        )

        # order by default ("created_ts")
        # default is backwards
        self._order_test([media3, media2, media1], None)
        self._order_test([media1, media2, media3], None, "f")
        self._order_test([media3, media2, media1], None, "b")

        # sort by media_id
        sorted_media = sorted([media1, media2, media3], reverse=False)
        sorted_media_reverse = sorted(sorted_media, reverse=True)

        # order by media_id
        self._order_test(sorted_media, "media_id")
        self._order_test(sorted_media, "media_id", "f")
        self._order_test(sorted_media_reverse, "media_id", "b")

        # order by upload_name
        self._order_test([media3, media2, media1], "upload_name")
        self._order_test([media3, media2, media1], "upload_name", "f")
        self._order_test([media1, media2, media3], "upload_name", "b")

        # order by media_type
        # result is ordered by media_id
        # because of uploaded media_type is always 'application/json'
        self._order_test(sorted_media, "media_type")
        self._order_test(sorted_media, "media_type", "f")
        self._order_test(sorted_media, "media_type", "b")

        # order by media_length
        self._order_test([media2, media3, media1], "media_length")
        self._order_test([media2, media3, media1], "media_length", "f")
        self._order_test([media1, media3, media2], "media_length", "b")

        # order by created_ts
        self._order_test([media1, media2, media3], "created_ts")
        self._order_test([media1, media2, media3], "created_ts", "f")
        self._order_test([media3, media2, media1], "created_ts", "b")

        # order by last_access_ts
        self._order_test([media1, media2, media3], "last_access_ts")
        self._order_test([media1, media2, media3], "last_access_ts", "f")
        self._order_test([media3, media2, media1], "last_access_ts", "b")

        # order by quarantined_by
        # one media is in quarantine, others are ordered by media_ids

        # Different sort order of SQlite and PostreSQL
        # If a media is not in quarantine `quarantined_by` is NULL
        # SQLite considers NULL to be smaller than any other value.
        # PostreSQL considers NULL to be larger than any other value.

        # self._order_test(sorted([media1, media2]) + [media3], "quarantined_by")
        # self._order_test(sorted([media1, media2]) + [media3], "quarantined_by", "f")
        # self._order_test([media3] + sorted([media1, media2]), "quarantined_by", "b")

        # order by safe_from_quarantine
        # one media is safe from quarantine, others are ordered by media_ids
        self._order_test(sorted([media1, media3]) + [media2], "safe_from_quarantine")
        self._order_test(
            sorted([media1, media3]) + [media2], "safe_from_quarantine", "f"
        )
        self._order_test(
            [media2] + sorted([media1, media3]), "safe_from_quarantine", "b"
        )

    def _create_media_for_user(self, user_token: str, number_media: int) -> List[str]:
        """
        Create a number of media for a specific user
        Args:
            user_token: Access token of the user
            number_media: Number of media to be created for the user
        Returns:
            List of created media ID
        """
        media_ids = []
        for _ in range(number_media):
            media_ids.append(self._create_media_and_access(user_token, SMALL_PNG))

        return media_ids

    def _create_media_and_access(
        self,
        user_token: str,
        image_data: bytes,
        filename: str = "image1.png",
    ) -> str:
        """
        Create one media for a specific user, access and returns `media_id`
        Args:
            user_token: Access token of the user
            image_data: binary data of image
            filename: The filename of the media to be uploaded
        Returns:
            The ID of the newly created media.
        """
        upload_resource = self.media_repo.children[b"upload"]
        download_resource = self.media_repo.children[b"download"]

        # Upload some media into the room
        response = self.helper.upload_media(
            upload_resource, image_data, user_token, filename, expect_code=200
        )

        # Extract media ID from the response
        server_and_media_id = response["content_uri"][6:]  # Cut off 'mxc://'
        media_id = server_and_media_id.split("/")[1]

        # Try to access a media and to create `last_access_ts`
        channel = make_request(
            self.reactor,
            FakeSite(download_resource, self.reactor),
            "GET",
            server_and_media_id,
            shorthand=False,
            access_token=user_token,
        )

        self.assertEqual(
            200,
            channel.code,
            msg=(
                f"Expected to receive a 200 on accessing media: {server_and_media_id}"
            ),
        )

        return media_id

    def _check_fields(self, content: List[JsonDict]) -> None:
        """Checks that the expected user attributes are present in content
        Args:
            content: List that is checked for content
        """
        for m in content:
            self.assertIn("media_id", m)
            self.assertIn("media_type", m)
            self.assertIn("media_length", m)
            self.assertIn("upload_name", m)
            self.assertIn("created_ts", m)
            self.assertIn("last_access_ts", m)
            self.assertIn("quarantined_by", m)
            self.assertIn("safe_from_quarantine", m)

    def _order_test(
        self,
        expected_media_list: List[str],
        order_by: Optional[str],
        dir: Optional[str] = None,
    ) -> None:
        """Request the list of media in a certain order. Assert that order is what
        we expect
        Args:
            expected_media_list: The list of media_ids in the order we expect to get
                back from the server
            order_by: The type of ordering to give the server
            dir: The direction of ordering to give the server
        """

        url = self.url + "?"
        if order_by is not None:
            url += f"order_by={order_by}&"
        if dir is not None and dir in ("b", "f"):
            url += f"dir={dir}"
        channel = self.make_request(
            "GET",
            url,
            access_token=self.admin_user_tok,
        )
        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual(channel.json_body["total"], len(expected_media_list))

        returned_order = [row["media_id"] for row in channel.json_body["media"]]
        self.assertEqual(expected_media_list, returned_order)
        self._check_fields(channel.json_body["media"])


class UserTokenRestTestCase(unittest.HomeserverTestCase):
    """Test for /_synapse/admin/v1/users/<user>/login"""

    servlets = [
        synapse.rest.admin.register_servlets,
        login.register_servlets,
        sync.register_servlets,
        room.register_servlets,
        devices.register_servlets,
        logout.register_servlets,
    ]

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self.store = hs.get_datastores().main

        self.admin_user = self.register_user("admin", "pass", admin=True)
        self.admin_user_tok = self.login("admin", "pass")

        self.other_user = self.register_user("user", "pass")
        self.other_user_tok = self.login("user", "pass")
        self.url = "/_synapse/admin/v1/users/%s/login" % urllib.parse.quote(
            self.other_user
        )

    def _get_token(self) -> str:
        channel = self.make_request(
            "POST", self.url, b"{}", access_token=self.admin_user_tok
        )
        self.assertEqual(200, channel.code, msg=channel.json_body)
        return channel.json_body["access_token"]

    def test_no_auth(self) -> None:
        """Try to login as a user without authentication."""
        channel = self.make_request("POST", self.url, b"{}")

        self.assertEqual(401, channel.code, msg=channel.json_body)
        self.assertEqual(Codes.MISSING_TOKEN, channel.json_body["errcode"])

    def test_not_admin(self) -> None:
        """Try to login as a user as a non-admin user."""
        channel = self.make_request(
            "POST", self.url, b"{}", access_token=self.other_user_tok
        )

        self.assertEqual(403, channel.code, msg=channel.json_body)

    def test_send_event(self) -> None:
        """Test that sending event as a user works."""
        # Create a room.
        room_id = self.helper.create_room_as(self.other_user, tok=self.other_user_tok)

        # Login in as the user
        puppet_token = self._get_token()

        # Test that sending works, and generates the event as the right user.
        resp = self.helper.send_event(room_id, "com.example.test", tok=puppet_token)
        event_id = resp["event_id"]
        event = self.get_success(self.store.get_event(event_id))
        self.assertEqual(event.sender, self.other_user)

    def test_devices(self) -> None:
        """Tests that logging in as a user doesn't create a new device for them."""
        # Login in as the user
        self._get_token()

        # Check that we don't see a new device in our devices list
        channel = self.make_request(
            "GET", "devices", b"{}", access_token=self.other_user_tok
        )
        self.assertEqual(200, channel.code, msg=channel.json_body)

        # We should only see the one device (from the login in `prepare`)
        self.assertEqual(len(channel.json_body["devices"]), 1)

    def test_logout(self) -> None:
        """Test that calling `/logout` with the token works."""
        # Login in as the user
        puppet_token = self._get_token()

        # Test that we can successfully make a request
        channel = self.make_request("GET", "devices", b"{}", access_token=puppet_token)
        self.assertEqual(200, channel.code, msg=channel.json_body)

        # Logout with the puppet token
        channel = self.make_request("POST", "logout", b"{}", access_token=puppet_token)
        self.assertEqual(200, channel.code, msg=channel.json_body)

        # The puppet token should no longer work
        channel = self.make_request("GET", "devices", b"{}", access_token=puppet_token)
        self.assertEqual(401, channel.code, msg=channel.json_body)

        # .. but the real user's tokens should still work
        channel = self.make_request(
            "GET", "devices", b"{}", access_token=self.other_user_tok
        )
        self.assertEqual(200, channel.code, msg=channel.json_body)

    def test_user_logout_all(self) -> None:
        """Tests that the target user calling `/logout/all` does *not* expire
        the token.
        """
        # Login in as the user
        puppet_token = self._get_token()

        # Test that we can successfully make a request
        channel = self.make_request("GET", "devices", b"{}", access_token=puppet_token)
        self.assertEqual(200, channel.code, msg=channel.json_body)

        # Logout all with the real user token
        channel = self.make_request(
            "POST", "logout/all", b"{}", access_token=self.other_user_tok
        )
        self.assertEqual(200, channel.code, msg=channel.json_body)

        # The puppet token should still work
        channel = self.make_request("GET", "devices", b"{}", access_token=puppet_token)
        self.assertEqual(200, channel.code, msg=channel.json_body)

        # .. but the real user's tokens shouldn't
        channel = self.make_request(
            "GET", "devices", b"{}", access_token=self.other_user_tok
        )
        self.assertEqual(401, channel.code, msg=channel.json_body)

    def test_admin_logout_all(self) -> None:
        """Tests that the admin user calling `/logout/all` does expire the
        token.
        """
        # Login in as the user
        puppet_token = self._get_token()

        # Test that we can successfully make a request
        channel = self.make_request("GET", "devices", b"{}", access_token=puppet_token)
        self.assertEqual(200, channel.code, msg=channel.json_body)

        # Logout all with the admin user token
        channel = self.make_request(
            "POST", "logout/all", b"{}", access_token=self.admin_user_tok
        )
        self.assertEqual(200, channel.code, msg=channel.json_body)

        # The puppet token should no longer work
        channel = self.make_request("GET", "devices", b"{}", access_token=puppet_token)
        self.assertEqual(401, channel.code, msg=channel.json_body)

        # .. but the real user's tokens should still work
        channel = self.make_request(
            "GET", "devices", b"{}", access_token=self.other_user_tok
        )
        self.assertEqual(200, channel.code, msg=channel.json_body)

    @unittest.override_config(
        {
            "public_baseurl": "https://example.org/",
            "user_consent": {
                "version": "1.0",
                "policy_name": "My Cool Privacy Policy",
                "template_dir": "/",
                "require_at_registration": True,
                "block_events_error": "You should accept the policy",
            },
            "form_secret": "123secret",
        }
    )
    def test_consent(self) -> None:
        """Test that sending a message is not subject to the privacy policies."""
        # Have the admin user accept the terms.
        self.get_success(self.store.user_set_consent_version(self.admin_user, "1.0"))

        # First, cheekily accept the terms and create a room
        self.get_success(self.store.user_set_consent_version(self.other_user, "1.0"))
        room_id = self.helper.create_room_as(self.other_user, tok=self.other_user_tok)
        self.helper.send_event(room_id, "com.example.test", tok=self.other_user_tok)

        # Now unaccept it and check that we can't send an event
        self.get_success(self.store.user_set_consent_version(self.other_user, "0.0"))
        self.helper.send_event(
            room_id,
            "com.example.test",
            tok=self.other_user_tok,
            expect_code=403,
        )

        # Login in as the user
        puppet_token = self._get_token()

        # Sending an event on their behalf should work fine
        self.helper.send_event(room_id, "com.example.test", tok=puppet_token)

    @override_config(
        {"limit_usage_by_mau": True, "max_mau_value": 1, "mau_trial_days": 0}
    )
    def test_mau_limit(self) -> None:
        # Create a room as the admin user. This will bump the monthly active users to 1.
        room_id = self.helper.create_room_as(self.admin_user, tok=self.admin_user_tok)

        # Trying to join as the other user should fail due to reaching MAU limit.
        self.helper.join(
            room_id,
            user=self.other_user,
            tok=self.other_user_tok,
            expect_code=403,
        )

        # Logging in as the other user and joining a room should work, even
        # though the MAU limit would stop the user doing so.
        puppet_token = self._get_token()
        self.helper.join(room_id, user=self.other_user, tok=puppet_token)


@parameterized_class(
    ("url_prefix",),
    [
        ("/_synapse/admin/v1/whois/%s",),
        ("/_matrix/client/r0/admin/whois/%s",),
    ],
)
class WhoisRestTestCase(unittest.HomeserverTestCase):

    servlets = [
        synapse.rest.admin.register_servlets,
        login.register_servlets,
    ]

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self.admin_user = self.register_user("admin", "pass", admin=True)
        self.admin_user_tok = self.login("admin", "pass")

        self.other_user = self.register_user("user", "pass")
        self.url = self.url_prefix % self.other_user  # type: ignore[attr-defined]

    def test_no_auth(self) -> None:
        """
        Try to get information of an user without authentication.
        """
        channel = self.make_request("GET", self.url, b"{}")
        self.assertEqual(401, channel.code, msg=channel.json_body)
        self.assertEqual(Codes.MISSING_TOKEN, channel.json_body["errcode"])

    def test_requester_is_not_admin(self) -> None:
        """
        If the user is not a server admin, an error is returned.
        """
        self.register_user("user2", "pass")
        other_user2_token = self.login("user2", "pass")

        channel = self.make_request(
            "GET",
            self.url,
            access_token=other_user2_token,
        )
        self.assertEqual(403, channel.code, msg=channel.json_body)
        self.assertEqual(Codes.FORBIDDEN, channel.json_body["errcode"])

    def test_user_is_not_local(self) -> None:
        """
        Tests that a lookup for a user that is not a local returns a 400
        """
        url = self.url_prefix % "@unknown_person:unknown_domain"  # type: ignore[attr-defined]

        channel = self.make_request(
            "GET",
            url,
            access_token=self.admin_user_tok,
        )
        self.assertEqual(400, channel.code, msg=channel.json_body)
        self.assertEqual("Can only whois a local user", channel.json_body["error"])

    def test_get_whois_admin(self) -> None:
        """
        The lookup should succeed for an admin.
        """
        channel = self.make_request(
            "GET",
            self.url,
            access_token=self.admin_user_tok,
        )
        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual(self.other_user, channel.json_body["user_id"])
        self.assertIn("devices", channel.json_body)

    def test_get_whois_user(self) -> None:
        """
        The lookup should succeed for a normal user looking up their own information.
        """
        other_user_token = self.login("user", "pass")

        channel = self.make_request(
            "GET",
            self.url,
            access_token=other_user_token,
        )
        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual(self.other_user, channel.json_body["user_id"])
        self.assertIn("devices", channel.json_body)


class ShadowBanRestTestCase(unittest.HomeserverTestCase):

    servlets = [
        synapse.rest.admin.register_servlets,
        login.register_servlets,
    ]

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self.store = hs.get_datastores().main

        self.admin_user = self.register_user("admin", "pass", admin=True)
        self.admin_user_tok = self.login("admin", "pass")

        self.other_user = self.register_user("user", "pass")

        self.url = "/_synapse/admin/v1/users/%s/shadow_ban" % urllib.parse.quote(
            self.other_user
        )

    @parameterized.expand(["POST", "DELETE"])
    def test_no_auth(self, method: str) -> None:
        """
        Try to get information of an user without authentication.
        """
        channel = self.make_request(method, self.url)
        self.assertEqual(401, channel.code, msg=channel.json_body)
        self.assertEqual(Codes.MISSING_TOKEN, channel.json_body["errcode"])

    @parameterized.expand(["POST", "DELETE"])
    def test_requester_is_not_admin(self, method: str) -> None:
        """
        If the user is not a server admin, an error is returned.
        """
        other_user_token = self.login("user", "pass")

        channel = self.make_request(method, self.url, access_token=other_user_token)
        self.assertEqual(403, channel.code, msg=channel.json_body)
        self.assertEqual(Codes.FORBIDDEN, channel.json_body["errcode"])

    @parameterized.expand(["POST", "DELETE"])
    def test_user_is_not_local(self, method: str) -> None:
        """
        Tests that shadow-banning for a user that is not a local returns a 400
        """
        url = "/_synapse/admin/v1/whois/@unknown_person:unknown_domain"

        channel = self.make_request(method, url, access_token=self.admin_user_tok)
        self.assertEqual(400, channel.code, msg=channel.json_body)

    def test_success(self) -> None:
        """
        Shadow-banning should succeed for an admin.
        """
        # The user starts off as not shadow-banned.
        other_user_token = self.login("user", "pass")
        result = self.get_success(self.store.get_user_by_access_token(other_user_token))
        assert result is not None
        self.assertFalse(result.shadow_banned)

        channel = self.make_request("POST", self.url, access_token=self.admin_user_tok)
        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual({}, channel.json_body)

        # Ensure the user is shadow-banned (and the cache was cleared).
        result = self.get_success(self.store.get_user_by_access_token(other_user_token))
        assert result is not None
        self.assertTrue(result.shadow_banned)

        # Un-shadow-ban the user.
        channel = self.make_request(
            "DELETE", self.url, access_token=self.admin_user_tok
        )
        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual({}, channel.json_body)

        # Ensure the user is no longer shadow-banned (and the cache was cleared).
        result = self.get_success(self.store.get_user_by_access_token(other_user_token))
        assert result is not None
        self.assertFalse(result.shadow_banned)


class RateLimitTestCase(unittest.HomeserverTestCase):

    servlets = [
        synapse.rest.admin.register_servlets,
        login.register_servlets,
    ]

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self.store = hs.get_datastores().main

        self.admin_user = self.register_user("admin", "pass", admin=True)
        self.admin_user_tok = self.login("admin", "pass")

        self.other_user = self.register_user("user", "pass")
        self.url = (
            "/_synapse/admin/v1/users/%s/override_ratelimit"
            % urllib.parse.quote(self.other_user)
        )

    @parameterized.expand(["GET", "POST", "DELETE"])
    def test_no_auth(self, method: str) -> None:
        """
        Try to get information of a user without authentication.
        """
        channel = self.make_request(method, self.url, b"{}")

        self.assertEqual(401, channel.code, msg=channel.json_body)
        self.assertEqual(Codes.MISSING_TOKEN, channel.json_body["errcode"])

    @parameterized.expand(["GET", "POST", "DELETE"])
    def test_requester_is_no_admin(self, method: str) -> None:
        """
        If the user is not a server admin, an error is returned.
        """
        other_user_token = self.login("user", "pass")

        channel = self.make_request(
            method,
            self.url,
            access_token=other_user_token,
        )

        self.assertEqual(403, channel.code, msg=channel.json_body)
        self.assertEqual(Codes.FORBIDDEN, channel.json_body["errcode"])

    @parameterized.expand(["GET", "POST", "DELETE"])
    def test_user_does_not_exist(self, method: str) -> None:
        """
        Tests that a lookup for a user that does not exist returns a 404
        """
        url = "/_synapse/admin/v1/users/@unknown_person:test/override_ratelimit"

        channel = self.make_request(
            method,
            url,
            access_token=self.admin_user_tok,
        )

        self.assertEqual(404, channel.code, msg=channel.json_body)
        self.assertEqual(Codes.NOT_FOUND, channel.json_body["errcode"])

    @parameterized.expand(
        [
            ("GET", "Can only look up local users"),
            ("POST", "Only local users can be ratelimited"),
            ("DELETE", "Only local users can be ratelimited"),
        ]
    )
    def test_user_is_not_local(self, method: str, error_msg: str) -> None:
        """
        Tests that a lookup for a user that is not a local returns a 400
        """
        url = (
            "/_synapse/admin/v1/users/@unknown_person:unknown_domain/override_ratelimit"
        )

        channel = self.make_request(
            method,
            url,
            access_token=self.admin_user_tok,
        )

        self.assertEqual(400, channel.code, msg=channel.json_body)
        self.assertEqual(error_msg, channel.json_body["error"])

    def test_invalid_parameter(self) -> None:
        """
        If parameters are invalid, an error is returned.
        """
        # messages_per_second is a string
        channel = self.make_request(
            "POST",
            self.url,
            access_token=self.admin_user_tok,
            content={"messages_per_second": "string"},
        )

        self.assertEqual(400, channel.code, msg=channel.json_body)
        self.assertEqual(Codes.INVALID_PARAM, channel.json_body["errcode"])

        # messages_per_second is negative
        channel = self.make_request(
            "POST",
            self.url,
            access_token=self.admin_user_tok,
            content={"messages_per_second": -1},
        )

        self.assertEqual(400, channel.code, msg=channel.json_body)
        self.assertEqual(Codes.INVALID_PARAM, channel.json_body["errcode"])

        # burst_count is a string
        channel = self.make_request(
            "POST",
            self.url,
            access_token=self.admin_user_tok,
            content={"burst_count": "string"},
        )

        self.assertEqual(400, channel.code, msg=channel.json_body)
        self.assertEqual(Codes.INVALID_PARAM, channel.json_body["errcode"])

        # burst_count is negative
        channel = self.make_request(
            "POST",
            self.url,
            access_token=self.admin_user_tok,
            content={"burst_count": -1},
        )

        self.assertEqual(400, channel.code, msg=channel.json_body)
        self.assertEqual(Codes.INVALID_PARAM, channel.json_body["errcode"])

    def test_return_zero_when_null(self) -> None:
        """
        If values in database are `null` API should return an int `0`
        """

        self.get_success(
            self.store.db_pool.simple_upsert(
                table="ratelimit_override",
                keyvalues={"user_id": self.other_user},
                values={
                    "messages_per_second": None,
                    "burst_count": None,
                },
            )
        )

        # request status
        channel = self.make_request(
            "GET",
            self.url,
            access_token=self.admin_user_tok,
        )
        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual(0, channel.json_body["messages_per_second"])
        self.assertEqual(0, channel.json_body["burst_count"])

    def test_success(self) -> None:
        """
        Rate-limiting (set/update/delete) should succeed for an admin.
        """
        # request status
        channel = self.make_request(
            "GET",
            self.url,
            access_token=self.admin_user_tok,
        )
        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertNotIn("messages_per_second", channel.json_body)
        self.assertNotIn("burst_count", channel.json_body)

        # set ratelimit
        channel = self.make_request(
            "POST",
            self.url,
            access_token=self.admin_user_tok,
            content={"messages_per_second": 10, "burst_count": 11},
        )
        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual(10, channel.json_body["messages_per_second"])
        self.assertEqual(11, channel.json_body["burst_count"])

        # update ratelimit
        channel = self.make_request(
            "POST",
            self.url,
            access_token=self.admin_user_tok,
            content={"messages_per_second": 20, "burst_count": 21},
        )
        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual(20, channel.json_body["messages_per_second"])
        self.assertEqual(21, channel.json_body["burst_count"])

        # request status
        channel = self.make_request(
            "GET",
            self.url,
            access_token=self.admin_user_tok,
        )
        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual(20, channel.json_body["messages_per_second"])
        self.assertEqual(21, channel.json_body["burst_count"])

        # delete ratelimit
        channel = self.make_request(
            "DELETE",
            self.url,
            access_token=self.admin_user_tok,
        )
        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertNotIn("messages_per_second", channel.json_body)
        self.assertNotIn("burst_count", channel.json_body)

        # request status
        channel = self.make_request(
            "GET",
            self.url,
            access_token=self.admin_user_tok,
        )
        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertNotIn("messages_per_second", channel.json_body)
        self.assertNotIn("burst_count", channel.json_body)


class AccountDataTestCase(unittest.HomeserverTestCase):

    servlets = [
        synapse.rest.admin.register_servlets,
        login.register_servlets,
    ]

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self.store = hs.get_datastores().main

        self.admin_user = self.register_user("admin", "pass", admin=True)
        self.admin_user_tok = self.login("admin", "pass")

        self.other_user = self.register_user("user", "pass")
        self.url = f"/_synapse/admin/v1/users/{self.other_user}/accountdata"

    def test_no_auth(self) -> None:
        """Try to get information of a user without authentication."""
        channel = self.make_request("GET", self.url, {})

        self.assertEqual(401, channel.code, msg=channel.json_body)
        self.assertEqual(Codes.MISSING_TOKEN, channel.json_body["errcode"])

    def test_requester_is_no_admin(self) -> None:
        """If the user is not a server admin, an error is returned."""
        other_user_token = self.login("user", "pass")

        channel = self.make_request(
            "GET",
            self.url,
            access_token=other_user_token,
        )

        self.assertEqual(403, channel.code, msg=channel.json_body)
        self.assertEqual(Codes.FORBIDDEN, channel.json_body["errcode"])

    def test_user_does_not_exist(self) -> None:
        """Tests that a lookup for a user that does not exist returns a 404"""
        url = "/_synapse/admin/v1/users/@unknown_person:test/override_ratelimit"

        channel = self.make_request(
            "GET",
            url,
            access_token=self.admin_user_tok,
        )

        self.assertEqual(404, channel.code, msg=channel.json_body)
        self.assertEqual(Codes.NOT_FOUND, channel.json_body["errcode"])

    def test_user_is_not_local(self) -> None:
        """Tests that a lookup for a user that is not a local returns a 400"""
        url = "/_synapse/admin/v1/users/@unknown_person:unknown_domain/accountdata"

        channel = self.make_request(
            "GET",
            url,
            access_token=self.admin_user_tok,
        )

        self.assertEqual(400, channel.code, msg=channel.json_body)
        self.assertEqual("Can only look up local users", channel.json_body["error"])

    def test_success(self) -> None:
        """Request account data should succeed for an admin."""

        # add account data
        self.get_success(
            self.store.add_account_data_for_user(self.other_user, "m.global", {"a": 1})
        )
        self.get_success(
            self.store.add_account_data_to_room(
                self.other_user, "test_room", "m.per_room", {"b": 2}
            )
        )

        channel = self.make_request(
            "GET",
            self.url,
            access_token=self.admin_user_tok,
        )
        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual(
            {"a": 1}, channel.json_body["account_data"]["global"]["m.global"]
        )
        self.assertEqual(
            {"b": 2},
            channel.json_body["account_data"]["rooms"]["test_room"]["m.per_room"],
        )


class UsersByExternalIdTestCase(unittest.HomeserverTestCase):

    servlets = [
        synapse.rest.admin.register_servlets,
        login.register_servlets,
    ]

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self.store = hs.get_datastores().main

        self.admin_user = self.register_user("admin", "pass", admin=True)
        self.admin_user_tok = self.login("admin", "pass")

        self.other_user = self.register_user("user", "pass")
        self.get_success(
            self.store.record_user_external_id(
                "the-auth-provider", "the-external-id", self.other_user
            )
        )
        self.get_success(
            self.store.record_user_external_id(
                "another-auth-provider", "a:complex@external/id", self.other_user
            )
        )

    def test_no_auth(self) -> None:
        """Try to lookup a user without authentication."""
        url = (
            "/_synapse/admin/v1/auth_providers/the-auth-provider/users/the-external-id"
        )

        channel = self.make_request(
            "GET",
            url,
        )

        self.assertEqual(401, channel.code, msg=channel.json_body)
        self.assertEqual(Codes.MISSING_TOKEN, channel.json_body["errcode"])

    def test_binding_does_not_exist(self) -> None:
        """Tests that a lookup for an external ID that does not exist returns a 404"""
        url = "/_synapse/admin/v1/auth_providers/the-auth-provider/users/unknown-id"

        channel = self.make_request(
            "GET",
            url,
            access_token=self.admin_user_tok,
        )

        self.assertEqual(404, channel.code, msg=channel.json_body)
        self.assertEqual(Codes.NOT_FOUND, channel.json_body["errcode"])

    def test_success(self) -> None:
        """Tests a successful external ID lookup"""
        url = (
            "/_synapse/admin/v1/auth_providers/the-auth-provider/users/the-external-id"
        )

        channel = self.make_request(
            "GET",
            url,
            access_token=self.admin_user_tok,
        )

        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual(
            {"user_id": self.other_user},
            channel.json_body,
        )

    def test_success_urlencoded(self) -> None:
        """Tests a successful external ID lookup with an url-encoded ID"""
        url = "/_synapse/admin/v1/auth_providers/another-auth-provider/users/a%3Acomplex%40external%2Fid"

        channel = self.make_request(
            "GET",
            url,
            access_token=self.admin_user_tok,
        )

        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual(
            {"user_id": self.other_user},
            channel.json_body,
        )
