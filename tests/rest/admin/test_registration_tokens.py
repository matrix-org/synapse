# Copyright 2021 Callum Brown
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

import synapse.rest.admin
from synapse.api.errors import Codes
from synapse.rest.client.v1 import login

from tests import unittest


class ManageRegistrationTokensTestCase(unittest.HomeserverTestCase):
    servlets = [
        synapse.rest.admin.register_servlets,
        login.register_servlets,
    ]

    def prepare(self, reactor, clock, hs):
        self.admin_user = self.register_user("admin", "pass", admin=True)
        self.admin_user_tok = self.login("admin", "pass")

        self.other_user = self.register_user("user", "pass")
        self.other_user_tok = self.login("user", "pass")

        self.url = "/_synapse/admin/v1/registration_tokens"

    def _new_token(self, data):
        """Helper function to create a token."""
        channel = self.make_request(
            "POST",
            self.url + "/new",
            data,
            access_token=self.admin_user_tok,
        )
        return channel.json_body["token"]

    # CREATION

    def test_create_no_auth(self):
        """Try to create a token without authentication."""
        channel = self.make_request("POST", self.url + "/new", {})
        self.assertEqual(401, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual(Codes.MISSING_TOKEN, channel.json_body["errcode"])

    def test_create_requester_not_admin(self):
        """Try to create a token while not an admin."""
        channel = self.make_request(
            "POST",
            self.url + "/new",
            {},
            access_token=self.other_user_tok,
        )
        self.assertEqual(403, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual(Codes.FORBIDDEN, channel.json_body["errcode"])

    def test_create_using_defaults(self):
        """Create a token using all the defaults."""
        channel = self.make_request(
            "POST",
            self.url + "/new",
            {},
            access_token=self.admin_user_tok,
        )

        self.assertEqual(200, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual(len(channel.json_body["token"]), 16)
        self.assertIsNone(channel.json_body["uses_allowed"])
        self.assertIsNone(channel.json_body["expiry_time"])
        self.assertEqual(channel.json_body["pending"], 0)
        self.assertEqual(channel.json_body["completed"], 0)

    def test_create_specifying_fields(self):
        """Create a token specifying the value of all fields."""
        data = {
            "token": "abcd",
            "uses_allowed": 1,
            "expiry_time": 1626427432000,
        }

        channel = self.make_request(
            "POST",
            self.url + "/new",
            data,
            access_token=self.admin_user_tok,
        )

        self.assertEqual(200, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual(channel.json_body["token"], "abcd")
        self.assertEqual(channel.json_body["uses_allowed"], 1)
        self.assertEqual(channel.json_body["expiry_time"], 1626427432000)
        self.assertEqual(channel.json_body["pending"], 0)
        self.assertEqual(channel.json_body["completed"], 0)

    def test_create_with_null_value(self):
        """Create a token specifying unlimited uses and no expiry."""
        data = {
            "uses_allowed": None,
            "expiry_time": None,
        }

        channel = self.make_request(
            "POST",
            self.url + "/new",
            data,
            access_token=self.admin_user_tok,
        )

        self.assertEqual(200, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual(len(channel.json_body["token"]), 16)
        self.assertIsNone(channel.json_body["uses_allowed"])
        self.assertIsNone(channel.json_body["expiry_time"])
        self.assertEqual(channel.json_body["pending"], 0)
        self.assertEqual(channel.json_body["completed"], 0)

    def test_create_token_too_long(self):
        """Check token longer than 64 chars is invalid."""
        data = {"token": "a" * 65}

        channel = self.make_request(
            "POST",
            self.url + "/new",
            data,
            access_token=self.admin_user_tok,
        )

        self.assertEqual(400, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual(channel.json_body["errcode"], Codes.INVALID_PARAM)

    def test_create_token_invalid_chars(self):
        """Check you can't create token with invalid characters."""
        data = {
            "token": "abc/def",
        }

        channel = self.make_request(
            "POST",
            self.url + "/new",
            data,
            access_token=self.admin_user_tok,
        )

        self.assertEqual(400, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual(channel.json_body["errcode"], Codes.INVALID_PARAM)

    def test_create_token_already_exists(self):
        """Check you can't create token that already exists."""
        data = {
            "token": "abcd",
        }

        channel1 = self.make_request(
            "POST",
            self.url + "/new",
            data,
            access_token=self.admin_user_tok,
        )
        self.assertEqual(200, int(channel1.result["code"]), msg=channel1.result["body"])

        channel2 = self.make_request(
            "POST",
            self.url + "/new",
            data,
            access_token=self.admin_user_tok,
        )
        self.assertEqual(400, int(channel2.result["code"]), msg=channel2.result["body"])
        self.assertEqual(channel2.json_body["errcode"], Codes.INVALID_PARAM)

    # UPDATING

    def test_update_no_auth(self):
        """Try to update a token without authentication."""
        channel = self.make_request(
            "PUT",
            self.url + "/1234",  # Token doesn't exist but that doesn't matter
            {},
        )
        self.assertEqual(401, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual(Codes.MISSING_TOKEN, channel.json_body["errcode"])

    def test_update_requester_not_admin(self):
        """Try to update a token while not an admin."""
        channel = self.make_request(
            "PUT",
            self.url + "/1234",  # Token doesn't exist but that doesn't matter
            {},
            access_token=self.other_user_tok,
        )
        self.assertEqual(403, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual(Codes.FORBIDDEN, channel.json_body["errcode"])

    def test_update_non_existent(self):
        """Try to update a token that doesn't exist."""
        channel = self.make_request(
            "PUT",
            self.url + "/1234",
            {"uses_allowed": 1},
            access_token=self.admin_user_tok,
        )

        self.assertEqual(404, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual(channel.json_body["errcode"], Codes.NOT_FOUND)

    def test_update_uses_allowed(self):
        """Test updating just uses_allowed."""
        # Create new token using default values
        token = self._new_token({})

        channel = self.make_request(
            "PUT",
            self.url + "/" + token,
            {"uses_allowed": 1},
            access_token=self.admin_user_tok,
        )

        self.assertEqual(200, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual(channel.json_body["uses_allowed"], 1)
        self.assertIsNone(channel.json_body["expiry_time"])

    def test_update_expiry_time(self):
        """Test updating just expiry_time."""
        # Create new token using default values
        token = self._new_token({})

        channel = self.make_request(
            "PUT",
            self.url + "/" + token,
            {"expiry_time": 1626430124000},
            access_token=self.admin_user_tok,
        )

        self.assertEqual(200, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual(channel.json_body["expiry_time"], 1626430124000)
        self.assertIsNone(channel.json_body["uses_allowed"])

    def test_update_both(self):
        """Test updating both uses_allowed and expiry_time."""
        # Create new token using default values
        token = self._new_token({})

        data = {
            "uses_allowed": 1,
            "expiry_time": 1626430124000,
        }

        channel = self.make_request(
            "PUT",
            self.url + "/" + token,
            data,
            access_token=self.admin_user_tok,
        )

        self.assertEqual(200, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual(channel.json_body["uses_allowed"], 1)
        self.assertEqual(channel.json_body["expiry_time"], 1626430124000)

    def test_update_invalid_type(self):
        """Test using invalid types doesn't work."""
        # Create new token using default values
        token = self._new_token({})

        data = {
            "uses_allowed": False,
            "expiry_time": "1626430124000",
        }

        channel = self.make_request(
            "PUT",
            self.url + "/" + token,
            data,
            access_token=self.admin_user_tok,
        )

        self.assertEqual(400, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual(channel.json_body["errcode"], Codes.INVALID_PARAM)

    # DELETING

    def test_delete_no_auth(self):
        """Try to delete a token without authentication."""
        channel = self.make_request(
            "DELETE",
            self.url + "/1234",  # Token doesn't exist but that doesn't matter
            {},
        )
        self.assertEqual(401, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual(Codes.MISSING_TOKEN, channel.json_body["errcode"])

    def test_delete_requester_not_admin(self):
        """Try to delete a token while not an admin."""
        channel = self.make_request(
            "DELETE",
            self.url + "/1234",  # Token doesn't exist but that doesn't matter
            {},
            access_token=self.other_user_tok,
        )
        self.assertEqual(403, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual(Codes.FORBIDDEN, channel.json_body["errcode"])

    def test_delete_non_existent(self):
        """Try to delete a token that doesn't exist."""
        channel = self.make_request(
            "DELETE",
            self.url + "/1234",
            {},
            access_token=self.admin_user_tok,
        )

        self.assertEqual(404, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual(channel.json_body["errcode"], Codes.NOT_FOUND)

    def test_delete(self):
        """Test deleting a token."""
        # Create new token using default values
        token = self._new_token({})

        channel = self.make_request(
            "DELETE",
            self.url + "/" + token,
            {},
            access_token=self.admin_user_tok,
        )

        self.assertEqual(200, int(channel.result["code"]), msg=channel.result["body"])

    # GETTING ONE

    def test_get_no_auth(self):
        """Try to get a token without authentication."""
        channel = self.make_request(
            "GET",
            self.url + "/1234",  # Token doesn't exist but that doesn't matter
            {},
        )
        self.assertEqual(401, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual(Codes.MISSING_TOKEN, channel.json_body["errcode"])

    def test_get_requester_not_admin(self):
        """Try to get a token while not an admin."""
        channel = self.make_request(
            "GET",
            self.url + "/1234",  # Token doesn't exist but that doesn't matter
            {},
            access_token=self.other_user_tok,
        )
        self.assertEqual(403, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual(Codes.FORBIDDEN, channel.json_body["errcode"])

    def test_get_non_existent(self):
        """Try to get a token that doesn't exist."""
        channel = self.make_request(
            "GET",
            self.url + "/1234",
            {},
            access_token=self.admin_user_tok,
        )

        self.assertEqual(404, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual(channel.json_body["errcode"], Codes.NOT_FOUND)

    def test_get(self):
        """Test getting a token."""
        # Create new token using default values
        token = self._new_token({})

        channel = self.make_request(
            "GET",
            self.url + "/" + token,
            {},
            access_token=self.admin_user_tok,
        )

        self.assertEqual(200, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual(channel.json_body["token"], token)
        self.assertIsNone(channel.json_body["uses_allowed"])
        self.assertIsNone(channel.json_body["expiry_time"])
        self.assertEqual(channel.json_body["pending"], 0)
        self.assertEqual(channel.json_body["completed"], 0)

    # LISTING

    def test_list_no_auth(self):
        """Try to list tokens without authentication."""
        channel = self.make_request("GET", self.url, {})
        self.assertEqual(401, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual(Codes.MISSING_TOKEN, channel.json_body["errcode"])

    def test_list_requester_not_admin(self):
        """Try to list tokens while not an admin."""
        channel = self.make_request(
            "GET",
            self.url,
            {},
            access_token=self.other_user_tok,
        )
        self.assertEqual(403, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual(Codes.FORBIDDEN, channel.json_body["errcode"])

    def test_list_all(self):
        """Test listing all tokens."""
        # Create new token using default values
        token = self._new_token({})

        channel = self.make_request(
            "GET",
            self.url,
            {},
            access_token=self.admin_user_tok,
        )

        self.assertEqual(200, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual(len(channel.json_body["registration_tokens"]), 1)
        token_info = channel.json_body["registration_tokens"][0]
        self.assertEqual(token_info["token"], token)
        self.assertIsNone(token_info["uses_allowed"])
        self.assertIsNone(token_info["expiry_time"])
        self.assertEqual(token_info["pending"], 0)
        self.assertEqual(token_info["completed"], 0)

    def test_list_invalid_query_parameter(self):
        """Test with `valid` query parameter not `true` or `false`."""
        channel = self.make_request(
            "GET",
            self.url + "?valid=x",
            {},
            access_token=self.admin_user_tok,
        )

        self.assertEqual(400, int(channel.result["code"]), msg=channel.result["body"])

    def test_list_valid(self):
        """Test listing just valid tokens."""
        now = self.hs.get_clock().time_msec()
        # Create always valid token
        token_valid_1 = self._new_token({})
        # Create token that hasn't been used up
        token_valid_2 = self._new_token({"uses_allowed": 1})
        # Create token that has expired
        self._new_token({"expiry_time": now - 10000})
        # Create token that has been used up but hasn't expired
        # Can't use API because it doesn't allow changing pending or completed
        store = self.hs.get_datastore()
        self.get_success(
            store.db_pool.simple_insert(
                "registration_tokens",
                {
                    "token": "invalid_2",
                    "uses_allowed": 2,
                    "pending": 1,
                    "completed": 1,
                    "expiry_time": now + 1000000,
                },
            )
        )

        channel = self.make_request(
            "GET",
            self.url + "?valid=true",
            {},
            access_token=self.admin_user_tok,
        )

        self.assertEqual(200, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual(len(channel.json_body["registration_tokens"]), 2)
        token_info_1 = channel.json_body["registration_tokens"][0]
        token_info_2 = channel.json_body["registration_tokens"][1]
        self.assertIn(token_info_1["token"], (token_valid_1, token_valid_2))
        self.assertIn(token_info_2["token"], (token_valid_1, token_valid_2))

    def test_list_invalid(self):
        """Test listing just invalid tokens."""
        now = self.hs.get_clock().time_msec()
        # Create always valid token
        self._new_token({})
        # Create token that hasn't been used up
        self._new_token({"uses_allowed": 1})
        # Create token that has expired
        token_invalid_1 = self._new_token({"expiry_time": now - 10000})
        # Create token that has been used up but hasn't expired
        # Can't use API because it doesn't allow changing pending or completed
        token_invalid_2 = "invalid_2"
        store = self.hs.get_datastore()
        self.get_success(
            store.db_pool.simple_insert(
                "registration_tokens",
                {
                    "token": token_invalid_2,
                    "uses_allowed": 2,
                    "pending": 1,
                    "completed": 1,
                    "expiry_time": now + 1000000,
                },
            )
        )

        channel = self.make_request(
            "GET",
            self.url + "?valid=false",
            {},
            access_token=self.admin_user_tok,
        )

        self.assertEqual(200, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual(len(channel.json_body["registration_tokens"]), 2)
        token_info_1 = channel.json_body["registration_tokens"][0]
        token_info_2 = channel.json_body["registration_tokens"][1]
        self.assertIn(token_info_1["token"], (token_invalid_1, token_invalid_2))
        self.assertIn(token_info_2["token"], (token_invalid_1, token_invalid_2))
