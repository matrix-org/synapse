# -*- coding: utf-8 -*-
# Copyright 2018 New Vector Ltd
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
import json

from mock import Mock

from synapse.http.server import JsonResource
from synapse.rest.client.v1.admin import register_servlets
from synapse.util import Clock

from tests import unittest
from tests.server import (
    ThreadedMemoryReactorClock,
    make_request,
    render,
    setup_test_homeserver,
)


class UserRegisterTestCase(unittest.TestCase):
    def setUp(self):

        self.clock = ThreadedMemoryReactorClock()
        self.hs_clock = Clock(self.clock)
        self.url = "/_matrix/client/r0/admin/register"

        self.registration_handler = Mock()
        self.identity_handler = Mock()
        self.login_handler = Mock()
        self.device_handler = Mock()
        self.device_handler.check_device_registered = Mock(return_value="FAKE")

        self.datastore = Mock(return_value=Mock())
        self.datastore.get_current_state_deltas = Mock(return_value=[])

        self.secrets = Mock()

        self.hs = setup_test_homeserver(
            self.addCleanup, http_client=None, clock=self.hs_clock, reactor=self.clock
        )

        self.hs.config.registration_shared_secret = u"shared"

        self.hs.get_media_repository = Mock()
        self.hs.get_deactivate_account_handler = Mock()

        self.resource = JsonResource(self.hs)
        register_servlets(self.hs, self.resource)

    def test_disabled(self):
        """
        If there is no shared secret, registration through this method will be
        prevented.
        """
        self.hs.config.registration_shared_secret = None

        request, channel = make_request("POST", self.url, b'{}')
        render(request, self.resource, self.clock)

        self.assertEqual(400, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual(
            'Shared secret registration is not enabled', channel.json_body["error"]
        )

    def test_get_nonce(self):
        """
        Calling GET on the endpoint will return a randomised nonce, using the
        homeserver's secrets provider.
        """
        secrets = Mock()
        secrets.token_hex = Mock(return_value="abcd")

        self.hs.get_secrets = Mock(return_value=secrets)

        request, channel = make_request("GET", self.url)
        render(request, self.resource, self.clock)

        self.assertEqual(channel.json_body, {"nonce": "abcd"})

    def test_expired_nonce(self):
        """
        Calling GET on the endpoint will return a randomised nonce, which will
        only last for SALT_TIMEOUT (60s).
        """
        request, channel = make_request("GET", self.url)
        render(request, self.resource, self.clock)
        nonce = channel.json_body["nonce"]

        # 59 seconds
        self.clock.advance(59)

        body = json.dumps({"nonce": nonce})
        request, channel = make_request("POST", self.url, body.encode('utf8'))
        render(request, self.resource, self.clock)

        self.assertEqual(400, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual('username must be specified', channel.json_body["error"])

        # 61 seconds
        self.clock.advance(2)

        request, channel = make_request("POST", self.url, body.encode('utf8'))
        render(request, self.resource, self.clock)

        self.assertEqual(400, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual('unrecognised nonce', channel.json_body["error"])

    def test_register_incorrect_nonce(self):
        """
        Only the provided nonce can be used, as it's checked in the MAC.
        """
        request, channel = make_request("GET", self.url)
        render(request, self.resource, self.clock)
        nonce = channel.json_body["nonce"]

        want_mac = hmac.new(key=b"shared", digestmod=hashlib.sha1)
        want_mac.update(b"notthenonce\x00bob\x00abc123\x00admin")
        want_mac = want_mac.hexdigest()

        body = json.dumps(
            {
                "nonce": nonce,
                "username": "bob",
                "password": "abc123",
                "admin": True,
                "mac": want_mac,
            }
        )
        request, channel = make_request("POST", self.url, body.encode('utf8'))
        render(request, self.resource, self.clock)

        self.assertEqual(403, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual("HMAC incorrect", channel.json_body["error"])

    def test_register_correct_nonce(self):
        """
        When the correct nonce is provided, and the right key is provided, the
        user is registered.
        """
        request, channel = make_request("GET", self.url)
        render(request, self.resource, self.clock)
        nonce = channel.json_body["nonce"]

        want_mac = hmac.new(key=b"shared", digestmod=hashlib.sha1)
        want_mac.update(nonce.encode('ascii') + b"\x00bob\x00abc123\x00admin")
        want_mac = want_mac.hexdigest()

        body = json.dumps(
            {
                "nonce": nonce,
                "username": "bob",
                "password": "abc123",
                "admin": True,
                "mac": want_mac,
            }
        )
        request, channel = make_request("POST", self.url, body.encode('utf8'))
        render(request, self.resource, self.clock)

        self.assertEqual(200, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual("@bob:test", channel.json_body["user_id"])

    def test_nonce_reuse(self):
        """
        A valid unrecognised nonce.
        """
        request, channel = make_request("GET", self.url)
        render(request, self.resource, self.clock)
        nonce = channel.json_body["nonce"]

        want_mac = hmac.new(key=b"shared", digestmod=hashlib.sha1)
        want_mac.update(nonce.encode('ascii') + b"\x00bob\x00abc123\x00admin")
        want_mac = want_mac.hexdigest()

        body = json.dumps(
            {
                "nonce": nonce,
                "username": "bob",
                "password": "abc123",
                "admin": True,
                "mac": want_mac,
            }
        )
        request, channel = make_request("POST", self.url, body.encode('utf8'))
        render(request, self.resource, self.clock)

        self.assertEqual(200, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual("@bob:test", channel.json_body["user_id"])

        # Now, try and reuse it
        request, channel = make_request("POST", self.url, body.encode('utf8'))
        render(request, self.resource, self.clock)

        self.assertEqual(400, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual('unrecognised nonce', channel.json_body["error"])

    def test_missing_parts(self):
        """
        Synapse will complain if you don't give nonce, username, password, and
        mac.  Admin is optional.  Additional checks are done for length and
        type.
        """

        def nonce():
            request, channel = make_request("GET", self.url)
            render(request, self.resource, self.clock)
            return channel.json_body["nonce"]

        #
        # Nonce check
        #

        # Must be present
        body = json.dumps({})
        request, channel = make_request("POST", self.url, body.encode('utf8'))
        render(request, self.resource, self.clock)

        self.assertEqual(400, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual('nonce must be specified', channel.json_body["error"])

        #
        # Username checks
        #

        # Must be present
        body = json.dumps({"nonce": nonce()})
        request, channel = make_request("POST", self.url, body.encode('utf8'))
        render(request, self.resource, self.clock)

        self.assertEqual(400, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual('username must be specified', channel.json_body["error"])

        # Must be a string
        body = json.dumps({"nonce": nonce(), "username": 1234})
        request, channel = make_request("POST", self.url, body.encode('utf8'))
        render(request, self.resource, self.clock)

        self.assertEqual(400, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual('Invalid username', channel.json_body["error"])

        # Must not have null bytes
        body = json.dumps({"nonce": nonce(), "username": u"abcd\u0000"})
        request, channel = make_request("POST", self.url, body.encode('utf8'))
        render(request, self.resource, self.clock)

        self.assertEqual(400, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual('Invalid username', channel.json_body["error"])

        # Must not have null bytes
        body = json.dumps({"nonce": nonce(), "username": "a" * 1000})
        request, channel = make_request("POST", self.url, body.encode('utf8'))
        render(request, self.resource, self.clock)

        self.assertEqual(400, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual('Invalid username', channel.json_body["error"])

        #
        # Username checks
        #

        # Must be present
        body = json.dumps({"nonce": nonce(), "username": "a"})
        request, channel = make_request("POST", self.url, body.encode('utf8'))
        render(request, self.resource, self.clock)

        self.assertEqual(400, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual('password must be specified', channel.json_body["error"])

        # Must be a string
        body = json.dumps({"nonce": nonce(), "username": "a", "password": 1234})
        request, channel = make_request("POST", self.url, body.encode('utf8'))
        render(request, self.resource, self.clock)

        self.assertEqual(400, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual('Invalid password', channel.json_body["error"])

        # Must not have null bytes
        body = json.dumps(
            {"nonce": nonce(), "username": "a", "password": u"abcd\u0000"}
        )
        request, channel = make_request("POST", self.url, body.encode('utf8'))
        render(request, self.resource, self.clock)

        self.assertEqual(400, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual('Invalid password', channel.json_body["error"])

        # Super long
        body = json.dumps({"nonce": nonce(), "username": "a", "password": "A" * 1000})
        request, channel = make_request("POST", self.url, body.encode('utf8'))
        render(request, self.resource, self.clock)

        self.assertEqual(400, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual('Invalid password', channel.json_body["error"])
