# -*- coding: utf-8 -*-
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
import synapse.rest.admin
from synapse.api.room_versions import KNOWN_ROOM_VERSIONS
from synapse.rest.client.v1 import login
from synapse.rest.client.v2_alpha import capabilities

from tests import unittest
from tests.unittest import override_config


class CapabilitiesTestCase(unittest.HomeserverTestCase):

    servlets = [
        synapse.rest.admin.register_servlets_for_client_rest_resource,
        capabilities.register_servlets,
        login.register_servlets,
    ]

    def make_homeserver(self, reactor, clock):
        self.url = b"/_matrix/client/r0/capabilities"
        hs = self.setup_test_homeserver()
        self.store = hs.get_datastore()
        self.config = hs.config
        self.auth_handler = hs.get_auth_handler()
        return hs

    def test_check_auth_required(self):
        channel = self.make_request("GET", self.url)

        self.assertEqual(channel.code, 401)

    def test_get_room_version_capabilities(self):
        self.register_user("user", "pass")
        access_token = self.login("user", "pass")

        channel = self.make_request("GET", self.url, access_token=access_token)
        capabilities = channel.json_body["capabilities"]

        self.assertEqual(channel.code, 200)
        for room_version in capabilities["m.room_versions"]["available"].keys():
            self.assertTrue(room_version in KNOWN_ROOM_VERSIONS, "" + room_version)

        self.assertEqual(
            self.config.default_room_version.identifier,
            capabilities["m.room_versions"]["default"],
        )

    def test_get_change_password_capabilities_password_login(self):
        localpart = "user"
        password = "pass"
        user = self.register_user(localpart, password)
        access_token = self.login(user, password)

        channel = self.make_request("GET", self.url, access_token=access_token)
        capabilities = channel.json_body["capabilities"]

        self.assertEqual(channel.code, 200)
        self.assertTrue(capabilities["m.change_password"]["enabled"])

    @override_config({"password_config": {"localdb_enabled": False}})
    def test_get_change_password_capabilities_localdb_disabled(self):
        localpart = "user"
        password = "pass"
        user = self.register_user(localpart, password)
        access_token = self.get_success(
            self.auth_handler.get_access_token_for_user_id(
                user, device_id=None, valid_until_ms=None
            )
        )

        channel = self.make_request("GET", self.url, access_token=access_token)
        capabilities = channel.json_body["capabilities"]

        self.assertEqual(channel.code, 200)
        self.assertFalse(capabilities["m.change_password"]["enabled"])

    @override_config({"password_config": {"enabled": False}})
    def test_get_change_password_capabilities_password_disabled(self):
        localpart = "user"
        password = "pass"
        user = self.register_user(localpart, password)
        access_token = self.get_success(
            self.auth_handler.get_access_token_for_user_id(
                user, device_id=None, valid_until_ms=None
            )
        )

        channel = self.make_request("GET", self.url, access_token=access_token)
        capabilities = channel.json_body["capabilities"]

        self.assertEqual(channel.code, 200)
        self.assertFalse(capabilities["m.change_password"]["enabled"])
