# Copyright 2019 New Vector Ltd
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
from http import HTTPStatus

from twisted.test.proto_helpers import MemoryReactor

import synapse.rest.admin
from synapse.api.room_versions import KNOWN_ROOM_VERSIONS
from synapse.rest.client import capabilities, login
from synapse.server import HomeServer
from synapse.util import Clock

from tests import unittest
from tests.unittest import override_config


class CapabilitiesTestCase(unittest.HomeserverTestCase):

    servlets = [
        synapse.rest.admin.register_servlets_for_client_rest_resource,
        capabilities.register_servlets,
        login.register_servlets,
    ]

    def make_homeserver(self, reactor: MemoryReactor, clock: Clock) -> HomeServer:
        self.url = b"/capabilities"
        hs = self.setup_test_homeserver()
        self.config = hs.config
        self.auth_handler = hs.get_auth_handler()
        return hs

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self.localpart = "user"
        self.password = "pass"
        self.user = self.register_user(self.localpart, self.password)

    def test_check_auth_required(self) -> None:
        channel = self.make_request("GET", self.url)

        self.assertEqual(channel.code, 401)

    def test_get_room_version_capabilities(self) -> None:
        access_token = self.login(self.localpart, self.password)

        channel = self.make_request("GET", self.url, access_token=access_token)
        capabilities = channel.json_body["capabilities"]

        self.assertEqual(channel.code, 200)
        for room_version in capabilities["m.room_versions"]["available"].keys():
            self.assertTrue(room_version in KNOWN_ROOM_VERSIONS, "" + room_version)

        self.assertEqual(
            self.config.server.default_room_version.identifier,
            capabilities["m.room_versions"]["default"],
        )

    def test_get_change_password_capabilities_password_login(self) -> None:
        access_token = self.login(self.localpart, self.password)

        channel = self.make_request("GET", self.url, access_token=access_token)
        capabilities = channel.json_body["capabilities"]

        self.assertEqual(channel.code, 200)
        self.assertTrue(capabilities["m.change_password"]["enabled"])

    @override_config({"password_config": {"localdb_enabled": False}})
    def test_get_change_password_capabilities_localdb_disabled(self) -> None:
        access_token = self.get_success(
            self.auth_handler.create_access_token_for_user_id(
                self.user, device_id=None, valid_until_ms=None
            )
        )

        channel = self.make_request("GET", self.url, access_token=access_token)
        capabilities = channel.json_body["capabilities"]

        self.assertEqual(channel.code, 200)
        self.assertFalse(capabilities["m.change_password"]["enabled"])

    @override_config({"password_config": {"enabled": False}})
    def test_get_change_password_capabilities_password_disabled(self) -> None:
        access_token = self.get_success(
            self.auth_handler.create_access_token_for_user_id(
                self.user, device_id=None, valid_until_ms=None
            )
        )

        channel = self.make_request("GET", self.url, access_token=access_token)
        capabilities = channel.json_body["capabilities"]

        self.assertEqual(channel.code, 200)
        self.assertFalse(capabilities["m.change_password"]["enabled"])

    def test_get_change_users_attributes_capabilities(self) -> None:
        """Test that server returns capabilities by default."""
        access_token = self.login(self.localpart, self.password)

        channel = self.make_request("GET", self.url, access_token=access_token)
        capabilities = channel.json_body["capabilities"]

        self.assertEqual(channel.code, HTTPStatus.OK)
        self.assertTrue(capabilities["m.change_password"]["enabled"])
        self.assertTrue(capabilities["m.set_displayname"]["enabled"])
        self.assertTrue(capabilities["m.set_avatar_url"]["enabled"])
        self.assertTrue(capabilities["m.3pid_changes"]["enabled"])

    @override_config({"enable_set_displayname": False})
    def test_get_set_displayname_capabilities_displayname_disabled(self) -> None:
        """Test if set displayname is disabled that the server responds it."""
        access_token = self.login(self.localpart, self.password)

        channel = self.make_request("GET", self.url, access_token=access_token)
        capabilities = channel.json_body["capabilities"]

        self.assertEqual(channel.code, HTTPStatus.OK)
        self.assertFalse(capabilities["m.set_displayname"]["enabled"])

    @override_config({"enable_set_avatar_url": False})
    def test_get_set_avatar_url_capabilities_avatar_url_disabled(self) -> None:
        """Test if set avatar_url is disabled that the server responds it."""
        access_token = self.login(self.localpart, self.password)

        channel = self.make_request("GET", self.url, access_token=access_token)
        capabilities = channel.json_body["capabilities"]

        self.assertEqual(channel.code, HTTPStatus.OK)
        self.assertFalse(capabilities["m.set_avatar_url"]["enabled"])

    @override_config({"enable_3pid_changes": False})
    def test_get_change_3pid_capabilities_3pid_disabled(self) -> None:
        """Test if change 3pid is disabled that the server responds it."""
        access_token = self.login(self.localpart, self.password)

        channel = self.make_request("GET", self.url, access_token=access_token)
        capabilities = channel.json_body["capabilities"]

        self.assertEqual(channel.code, HTTPStatus.OK)
        self.assertFalse(capabilities["m.3pid_changes"]["enabled"])

    @override_config({"experimental_features": {"msc3244_enabled": False}})
    def test_get_does_not_include_msc3244_fields_when_disabled(self) -> None:
        access_token = self.get_success(
            self.auth_handler.create_access_token_for_user_id(
                self.user, device_id=None, valid_until_ms=None
            )
        )

        channel = self.make_request("GET", self.url, access_token=access_token)
        capabilities = channel.json_body["capabilities"]

        self.assertEqual(channel.code, 200)
        self.assertNotIn(
            "org.matrix.msc3244.room_capabilities", capabilities["m.room_versions"]
        )

    def test_get_does_include_msc3244_fields_when_enabled(self) -> None:
        access_token = self.get_success(
            self.auth_handler.create_access_token_for_user_id(
                self.user, device_id=None, valid_until_ms=None
            )
        )

        channel = self.make_request("GET", self.url, access_token=access_token)
        capabilities = channel.json_body["capabilities"]

        self.assertEqual(channel.code, 200)
        for details in capabilities["m.room_versions"][
            "org.matrix.msc3244.room_capabilities"
        ].values():
            if details["preferred"] is not None:
                self.assertTrue(
                    details["preferred"] in KNOWN_ROOM_VERSIONS,
                    str(details["preferred"]),
                )

            self.assertGreater(len(details["support"]), 0)
            for room_version in details["support"]:
                self.assertTrue(room_version in KNOWN_ROOM_VERSIONS, str(room_version))
