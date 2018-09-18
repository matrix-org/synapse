# -*- coding: utf-8 -*-
# Copyright 2016 OpenMarket Ltd
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

from twisted.internet import defer

from synapse.http.site import XForwardedForRequest
from synapse.rest.client.v1 import admin, login

from tests import unittest


class ClientIpStoreTestCase(unittest.HomeserverTestCase):
    def make_homeserver(self, reactor, clock):
        hs = self.setup_test_homeserver()
        return hs

    def prepare(self, hs, reactor, clock):
        self.store = self.hs.get_datastore()

    def test_insert_new_client_ip(self):
        self.reactor.advance(12345678)

        user_id = "@user:id"
        self.get_success(
            self.store.insert_client_ip(
                user_id, "access_token", "ip", "user_agent", "device_id"
            )
        )

        # Trigger the storage loop
        self.reactor.advance(10)

        result = self.get_success(
            self.store.get_last_client_ip_by_device(user_id, "device_id")
        )

        r = result[(user_id, "device_id")]
        self.assertDictContainsSubset(
            {
                "user_id": user_id,
                "device_id": "device_id",
                "access_token": "access_token",
                "ip": "ip",
                "user_agent": "user_agent",
                "last_seen": 12345678000,
            },
            r,
        )

    def test_disabled_monthly_active_user(self):
        self.hs.config.limit_usage_by_mau = False
        self.hs.config.max_mau_value = 50
        user_id = "@user:server"
        self.get_success(
            self.store.insert_client_ip(
                user_id, "access_token", "ip", "user_agent", "device_id"
            )
        )
        active = self.get_success(self.store.user_last_seen_monthly_active(user_id))
        self.assertFalse(active)

    def test_adding_monthly_active_user_when_full(self):
        self.hs.config.limit_usage_by_mau = True
        self.hs.config.max_mau_value = 50
        lots_of_users = 100
        user_id = "@user:server"

        self.store.get_monthly_active_count = Mock(
            return_value=defer.succeed(lots_of_users)
        )
        self.get_success(
            self.store.insert_client_ip(
                user_id, "access_token", "ip", "user_agent", "device_id"
            )
        )
        active = self.get_success(self.store.user_last_seen_monthly_active(user_id))
        self.assertFalse(active)

    def test_adding_monthly_active_user_when_space(self):
        self.hs.config.limit_usage_by_mau = True
        self.hs.config.max_mau_value = 50
        user_id = "@user:server"
        active = self.get_success(self.store.user_last_seen_monthly_active(user_id))
        self.assertFalse(active)

        # Trigger the saving loop
        self.reactor.advance(10)

        self.get_success(
            self.store.insert_client_ip(
                user_id, "access_token", "ip", "user_agent", "device_id"
            )
        )
        active = self.get_success(self.store.user_last_seen_monthly_active(user_id))
        self.assertTrue(active)

    def test_updating_monthly_active_user_when_space(self):
        self.hs.config.limit_usage_by_mau = True
        self.hs.config.max_mau_value = 50
        user_id = "@user:server"
        self.get_success(
            self.store.register(user_id=user_id, token="123", password_hash=None)
        )

        active = self.get_success(self.store.user_last_seen_monthly_active(user_id))
        self.assertFalse(active)

        # Trigger the saving loop
        self.reactor.advance(10)

        self.get_success(
            self.store.insert_client_ip(
                user_id, "access_token", "ip", "user_agent", "device_id"
            )
        )
        active = self.get_success(self.store.user_last_seen_monthly_active(user_id))
        self.assertTrue(active)


class ClientIpAuthTestCase(unittest.HomeserverTestCase):

    servlets = [admin.register_servlets, login.register_servlets]

    def make_homeserver(self, reactor, clock):
        hs = self.setup_test_homeserver()
        return hs

    def prepare(self, hs, reactor, clock):
        self.hs.config.registration_shared_secret = u"shared"
        self.store = self.hs.get_datastore()

        # Create the user
        request, channel = self.make_request("GET", "/_matrix/client/r0/admin/register")
        self.render(request)
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
        request, channel = self.make_request(
            "POST", "/_matrix/client/r0/admin/register", body.encode('utf8')
        )
        self.render(request)

        self.assertEqual(channel.code, 200)
        self.user_id = channel.json_body["user_id"]

    def test_request_with_xforwarded(self):
        """
        The IP in X-Forwarded-For is entered into the client IPs table.
        """
        self._runtest(
            {b"X-Forwarded-For": b"127.9.0.1"},
            "127.9.0.1",
            {"request": XForwardedForRequest},
        )

    def test_request_from_getPeer(self):
        """
        The IP returned by getPeer is entered into the client IPs table, if
        there's no X-Forwarded-For header.
        """
        self._runtest({}, "127.0.0.1", {})

    def _runtest(self, headers, expected_ip, make_request_args):
        device_id = "bleb"

        body = json.dumps(
            {
                "type": "m.login.password",
                "user": "bob",
                "password": "abc123",
                "device_id": device_id,
            }
        )
        request, channel = self.make_request(
            "POST", "/_matrix/client/r0/login", body.encode('utf8'), **make_request_args
        )
        self.render(request)
        self.assertEqual(channel.code, 200)
        access_token = channel.json_body["access_token"].encode('ascii')

        # Advance to a known time
        self.reactor.advance(123456 - self.reactor.seconds())

        request, channel = self.make_request(
            "GET",
            "/_matrix/client/r0/admin/users/" + self.user_id,
            body.encode('utf8'),
            access_token=access_token,
            **make_request_args
        )
        request.requestHeaders.addRawHeader(b"User-Agent", b"Mozzila pizza")

        # Add the optional headers
        for h, v in headers.items():
            request.requestHeaders.addRawHeader(h, v)
        self.render(request)

        # Advance so the save loop occurs
        self.reactor.advance(100)

        result = self.get_success(
            self.store.get_last_client_ip_by_device(self.user_id, device_id)
        )
        r = result[(self.user_id, device_id)]
        self.assertDictContainsSubset(
            {
                "user_id": self.user_id,
                "device_id": device_id,
                "ip": expected_ip,
                "user_agent": "Mozzila pizza",
                "last_seen": 123456100,
            },
            r,
        )
