# -*- coding: utf-8 -*-
# Copyright 2020 Dirk Klimpel
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

import json
import urllib.parse

import synapse.rest.admin
from synapse.api.errors import Codes
from synapse.rest.client.v1 import login

from tests import unittest


class DeviceRestTestCase(unittest.HomeserverTestCase):

    servlets = [
        synapse.rest.admin.register_servlets,
        login.register_servlets,
    ]

    def prepare(self, reactor, clock, hs):
        self.handler = hs.get_device_handler()

        self.admin_user = self.register_user("admin", "pass", admin=True)
        self.admin_user_tok = self.login("admin", "pass")

        self.other_user = self.register_user("user", "pass")
        self.other_user_token = self.login("user", "pass")
        res = self.get_success(self.handler.get_devices_by_user(self.other_user))
        self.other_user_device_id = res[0]["device_id"]

        self.url = "/_synapse/admin/v2/users/%s/devices/%s" % (
            urllib.parse.quote(self.other_user),
            self.other_user_device_id,
        )

    def test_no_auth(self):
        """
        Try to get a device of an user without authentication.
        """
        request, channel = self.make_request("GET", self.url, b"{}")
        self.render(request)

        self.assertEqual(401, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual(Codes.MISSING_TOKEN, channel.json_body["errcode"])

        request, channel = self.make_request("PUT", self.url, b"{}")
        self.render(request)

        self.assertEqual(401, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual(Codes.MISSING_TOKEN, channel.json_body["errcode"])

        request, channel = self.make_request("DELETE", self.url, b"{}")
        self.render(request)

        self.assertEqual(401, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual(Codes.MISSING_TOKEN, channel.json_body["errcode"])

    def test_requester_is_no_admin(self):
        """
        If the user is not a server admin, an error is returned.
        """
        request, channel = self.make_request(
            "GET", self.url, access_token=self.other_user_token,
        )
        self.render(request)

        self.assertEqual(403, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual(Codes.FORBIDDEN, channel.json_body["errcode"])

        request, channel = self.make_request(
            "PUT", self.url, access_token=self.other_user_token,
        )
        self.render(request)

        self.assertEqual(403, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual(Codes.FORBIDDEN, channel.json_body["errcode"])

        request, channel = self.make_request(
            "DELETE", self.url, access_token=self.other_user_token,
        )
        self.render(request)

        self.assertEqual(403, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual(Codes.FORBIDDEN, channel.json_body["errcode"])

    def test_user_does_not_exist(self):
        """
        Tests that a lookup for a user that does not exist returns a 404
        """
        url = (
            "/_synapse/admin/v2/users/@unknown_person:test/devices/%s"
            % self.other_user_device_id
        )

        request, channel = self.make_request(
            "GET", url, access_token=self.admin_user_tok,
        )
        self.render(request)

        self.assertEqual(404, channel.code, msg=channel.json_body)
        self.assertEqual(Codes.NOT_FOUND, channel.json_body["errcode"])

        request, channel = self.make_request(
            "PUT", url, access_token=self.admin_user_tok,
        )
        self.render(request)

        self.assertEqual(404, channel.code, msg=channel.json_body)
        self.assertEqual(Codes.NOT_FOUND, channel.json_body["errcode"])

        request, channel = self.make_request(
            "DELETE", url, access_token=self.admin_user_tok,
        )
        self.render(request)

        self.assertEqual(404, channel.code, msg=channel.json_body)
        self.assertEqual(Codes.NOT_FOUND, channel.json_body["errcode"])

    def test_user_is_not_local(self):
        """
        Tests that a lookup for a user that is not a local returns a 400
        """
        url = (
            "/_synapse/admin/v2/users/@unknown_person:unknown_domain/devices/%s"
            % self.other_user_device_id
        )

        request, channel = self.make_request(
            "GET", url, access_token=self.admin_user_tok,
        )
        self.render(request)

        self.assertEqual(400, channel.code, msg=channel.json_body)
        self.assertEqual("Can only lookup local users", channel.json_body["error"])

        request, channel = self.make_request(
            "PUT", url, access_token=self.admin_user_tok,
        )
        self.render(request)

        self.assertEqual(400, channel.code, msg=channel.json_body)
        self.assertEqual("Can only lookup local users", channel.json_body["error"])

        request, channel = self.make_request(
            "DELETE", url, access_token=self.admin_user_tok,
        )
        self.render(request)

        self.assertEqual(400, channel.code, msg=channel.json_body)
        self.assertEqual("Can only lookup local users", channel.json_body["error"])

    def test_unknown_device(self):
        """
        Tests that a lookup for a device that does not exist returns either 404 or 200.
        """
        url = "/_synapse/admin/v2/users/%s/devices/unknown_device" % urllib.parse.quote(
            self.other_user
        )

        request, channel = self.make_request(
            "GET", url, access_token=self.admin_user_tok,
        )
        self.render(request)

        self.assertEqual(404, channel.code, msg=channel.json_body)
        self.assertEqual(Codes.NOT_FOUND, channel.json_body["errcode"])

        request, channel = self.make_request(
            "PUT", url, access_token=self.admin_user_tok,
        )
        self.render(request)

        self.assertEqual(200, channel.code, msg=channel.json_body)

        request, channel = self.make_request(
            "DELETE", url, access_token=self.admin_user_tok,
        )
        self.render(request)

        # Delete unknown device returns status 200
        self.assertEqual(200, channel.code, msg=channel.json_body)

    def test_update_device_too_long_display_name(self):
        """
        Update a device with a display name that is invalid (too long).
        """
        # Set iniital display name.
        update = {"display_name": "new display"}
        self.get_success(
            self.handler.update_device(
                self.other_user, self.other_user_device_id, update
            )
        )

        # Request to update a device display name with a new value that is longer than allowed.
        update = {
            "display_name": "a"
            * (synapse.handlers.device.MAX_DEVICE_DISPLAY_NAME_LEN + 1)
        }

        body = json.dumps(update)
        request, channel = self.make_request(
            "PUT",
            self.url,
            access_token=self.admin_user_tok,
            content=body.encode(encoding="utf_8"),
        )
        self.render(request)

        self.assertEqual(400, channel.code, msg=channel.json_body)
        self.assertEqual(Codes.TOO_LARGE, channel.json_body["errcode"])

        # Ensure the display name was not updated.
        request, channel = self.make_request(
            "GET", self.url, access_token=self.admin_user_tok,
        )
        self.render(request)

        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual("new display", channel.json_body["display_name"])

    def test_update_no_display_name(self):
        """
        Tests that a update for a device without JSON returns a 200
        """
        # Set iniital display name.
        update = {"display_name": "new display"}
        self.get_success(
            self.handler.update_device(
                self.other_user, self.other_user_device_id, update
            )
        )

        request, channel = self.make_request(
            "PUT", self.url, access_token=self.admin_user_tok,
        )
        self.render(request)

        self.assertEqual(200, channel.code, msg=channel.json_body)

        # Ensure the display name was not updated.
        request, channel = self.make_request(
            "GET", self.url, access_token=self.admin_user_tok,
        )
        self.render(request)

        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual("new display", channel.json_body["display_name"])

    def test_update_display_name(self):
        """
        Tests a normal successful update of display name
        """
        # Set new display_name
        body = json.dumps({"display_name": "new displayname"})
        request, channel = self.make_request(
            "PUT",
            self.url,
            access_token=self.admin_user_tok,
            content=body.encode(encoding="utf_8"),
        )
        self.render(request)

        self.assertEqual(200, channel.code, msg=channel.json_body)

        # Check new display_name
        request, channel = self.make_request(
            "GET", self.url, access_token=self.admin_user_tok,
        )
        self.render(request)

        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual("new displayname", channel.json_body["display_name"])

    def test_get_device(self):
        """
        Tests that a normal lookup for a device is successfully
        """
        request, channel = self.make_request(
            "GET", self.url, access_token=self.admin_user_tok,
        )
        self.render(request)

        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual(self.other_user, channel.json_body["user_id"])
        # Check that all fields are available
        self.assertIn("user_id", channel.json_body)
        self.assertIn("device_id", channel.json_body)
        self.assertIn("display_name", channel.json_body)
        self.assertIn("last_seen_ip", channel.json_body)
        self.assertIn("last_seen_ts", channel.json_body)

    def test_delete_device(self):
        """
        Tests that a remove of a device is successfully
        """
        # Count number of devies of an user.
        res = self.get_success(self.handler.get_devices_by_user(self.other_user))
        number_devices = len(res)
        self.assertEqual(1, number_devices)

        # Delete device
        request, channel = self.make_request(
            "DELETE", self.url, access_token=self.admin_user_tok,
        )
        self.render(request)

        self.assertEqual(200, channel.code, msg=channel.json_body)

        # Ensure that the number of devices is decreased
        res = self.get_success(self.handler.get_devices_by_user(self.other_user))
        self.assertEqual(number_devices - 1, len(res))


class DevicesRestTestCase(unittest.HomeserverTestCase):

    servlets = [
        synapse.rest.admin.register_servlets,
        login.register_servlets,
    ]

    def prepare(self, reactor, clock, hs):
        self.admin_user = self.register_user("admin", "pass", admin=True)
        self.admin_user_tok = self.login("admin", "pass")

        self.other_user = self.register_user("user", "pass")

        self.url = "/_synapse/admin/v2/users/%s/devices" % urllib.parse.quote(
            self.other_user
        )

    def test_no_auth(self):
        """
        Try to list devices of an user without authentication.
        """
        request, channel = self.make_request("GET", self.url, b"{}")
        self.render(request)

        self.assertEqual(401, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual(Codes.MISSING_TOKEN, channel.json_body["errcode"])

    def test_requester_is_no_admin(self):
        """
        If the user is not a server admin, an error is returned.
        """
        other_user_token = self.login("user", "pass")

        request, channel = self.make_request(
            "GET", self.url, access_token=other_user_token,
        )
        self.render(request)

        self.assertEqual(403, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual(Codes.FORBIDDEN, channel.json_body["errcode"])

    def test_user_does_not_exist(self):
        """
        Tests that a lookup for a user that does not exist returns a 404
        """
        url = "/_synapse/admin/v2/users/@unknown_person:test/devices"
        request, channel = self.make_request(
            "GET", url, access_token=self.admin_user_tok,
        )
        self.render(request)

        self.assertEqual(404, channel.code, msg=channel.json_body)
        self.assertEqual(Codes.NOT_FOUND, channel.json_body["errcode"])

    def test_user_is_not_local(self):
        """
        Tests that a lookup for a user that is not a local returns a 400
        """
        url = "/_synapse/admin/v2/users/@unknown_person:unknown_domain/devices"

        request, channel = self.make_request(
            "GET", url, access_token=self.admin_user_tok,
        )
        self.render(request)

        self.assertEqual(400, channel.code, msg=channel.json_body)
        self.assertEqual("Can only lookup local users", channel.json_body["error"])

    def test_get_devices(self):
        """
        Tests that a normal lookup for devices is successfully
        """
        # Create devices
        number_devices = 5
        for n in range(number_devices):
            self.login("user", "pass")

        # Get devices
        request, channel = self.make_request(
            "GET", self.url, access_token=self.admin_user_tok,
        )
        self.render(request)

        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual(number_devices, len(channel.json_body["devices"]))
        self.assertEqual(self.other_user, channel.json_body["devices"][0]["user_id"])
        # Check that all fields are available
        for d in channel.json_body["devices"]:
            self.assertIn("user_id", d)
            self.assertIn("device_id", d)
            self.assertIn("display_name", d)
            self.assertIn("last_seen_ip", d)
            self.assertIn("last_seen_ts", d)


class DeleteDevicesRestTestCase(unittest.HomeserverTestCase):

    servlets = [
        synapse.rest.admin.register_servlets,
        login.register_servlets,
    ]

    def prepare(self, reactor, clock, hs):
        self.handler = hs.get_device_handler()

        self.admin_user = self.register_user("admin", "pass", admin=True)
        self.admin_user_tok = self.login("admin", "pass")

        self.other_user = self.register_user("user", "pass")

        self.url = "/_synapse/admin/v2/users/%s/delete_devices" % urllib.parse.quote(
            self.other_user
        )

    def test_no_auth(self):
        """
        Try to delete devices of an user without authentication.
        """
        request, channel = self.make_request("POST", self.url, b"{}")
        self.render(request)

        self.assertEqual(401, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual(Codes.MISSING_TOKEN, channel.json_body["errcode"])

    def test_requester_is_no_admin(self):
        """
        If the user is not a server admin, an error is returned.
        """
        other_user_token = self.login("user", "pass")

        request, channel = self.make_request(
            "POST", self.url, access_token=other_user_token,
        )
        self.render(request)

        self.assertEqual(403, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual(Codes.FORBIDDEN, channel.json_body["errcode"])

    def test_user_does_not_exist(self):
        """
        Tests that a lookup for a user that does not exist returns a 404
        """
        url = "/_synapse/admin/v2/users/@unknown_person:test/delete_devices"
        request, channel = self.make_request(
            "POST", url, access_token=self.admin_user_tok,
        )
        self.render(request)

        self.assertEqual(404, channel.code, msg=channel.json_body)
        self.assertEqual(Codes.NOT_FOUND, channel.json_body["errcode"])

    def test_user_is_not_local(self):
        """
        Tests that a lookup for a user that is not a local returns a 400
        """
        url = "/_synapse/admin/v2/users/@unknown_person:unknown_domain/delete_devices"

        request, channel = self.make_request(
            "POST", url, access_token=self.admin_user_tok,
        )
        self.render(request)

        self.assertEqual(400, channel.code, msg=channel.json_body)
        self.assertEqual("Can only lookup local users", channel.json_body["error"])

    def test_unknown_devices(self):
        """
        Tests that a remove of a device that does not exist returns 200.
        """
        body = json.dumps({"devices": ["unknown_device1", "unknown_device2"]})
        request, channel = self.make_request(
            "POST",
            self.url,
            access_token=self.admin_user_tok,
            content=body.encode(encoding="utf_8"),
        )
        self.render(request)

        # Delete unknown devices returns status 200
        self.assertEqual(200, channel.code, msg=channel.json_body)

    def test_delete_devices(self):
        """
        Tests that a remove of devices is successfully
        """

        # Create devices
        number_devices = 5
        for n in range(number_devices):
            self.login("user", "pass")

        # Get devices
        res = self.get_success(self.handler.get_devices_by_user(self.other_user))
        self.assertEqual(number_devices, len(res))

        # Create list of device IDs
        device_ids = []
        for d in res:
            device_ids.append(str(d["device_id"]))

        # Delete devices
        body = json.dumps({"devices": device_ids})
        request, channel = self.make_request(
            "POST",
            self.url,
            access_token=self.admin_user_tok,
            content=body.encode(encoding="utf_8"),
        )
        self.render(request)

        self.assertEqual(200, channel.code, msg=channel.json_body)

        res = self.get_success(self.handler.get_devices_by_user(self.other_user))
        self.assertEqual(0, len(res))
