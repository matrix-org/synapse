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

"""Tests REST events for /rooms paths."""

import json

from mock import Mock, NonCallableMock

from synapse.api.constants import LoginType
from synapse.api.errors import Codes, HttpResponseException, SynapseError
from synapse.http.server import JsonResource
from synapse.rest.client.v2_alpha import register, sync
from synapse.util import Clock

from tests import unittest
from tests.server import (
    ThreadedMemoryReactorClock,
    make_request,
    render,
    setup_test_homeserver,
)


class TestMauLimit(unittest.TestCase):
    def setUp(self):
        self.reactor = ThreadedMemoryReactorClock()
        self.clock = Clock(self.reactor)

        self.hs = setup_test_homeserver(
            self.addCleanup,
            "red",
            http_client=None,
            clock=self.clock,
            reactor=self.reactor,
            federation_client=Mock(),
            ratelimiter=NonCallableMock(spec_set=["send_message"]),
        )

        self.store = self.hs.get_datastore()

        self.hs.config.registrations_require_3pid = []
        self.hs.config.enable_registration_captcha = False
        self.hs.config.recaptcha_public_key = []

        self.hs.config.limit_usage_by_mau = True
        self.hs.config.hs_disabled = False
        self.hs.config.max_mau_value = 2
        self.hs.config.mau_trial_days = 0
        self.hs.config.server_notices_mxid = "@server:red"
        self.hs.config.server_notices_mxid_display_name = None
        self.hs.config.server_notices_mxid_avatar_url = None
        self.hs.config.server_notices_room_name = "Test Server Notice Room"

        self.resource = JsonResource(self.hs)
        register.register_servlets(self.hs, self.resource)
        sync.register_servlets(self.hs, self.resource)

    def test_simple_deny_mau(self):
        # Create and sync so that the MAU counts get updated
        token1 = self.create_user("kermit1")
        self.do_sync_for_user(token1)
        token2 = self.create_user("kermit2")
        self.do_sync_for_user(token2)

        # We've created and activated two users, we shouldn't be able to
        # register new users
        with self.assertRaises(SynapseError) as cm:
            self.create_user("kermit3")

        e = cm.exception
        self.assertEqual(e.code, 403)
        self.assertEqual(e.errcode, Codes.RESOURCE_LIMIT_EXCEEDED)

    def test_allowed_after_a_month_mau(self):
        # Create and sync so that the MAU counts get updated
        token1 = self.create_user("kermit1")
        self.do_sync_for_user(token1)
        token2 = self.create_user("kermit2")
        self.do_sync_for_user(token2)

        # Advance time by 31 days
        self.reactor.advance(31 * 24 * 60 * 60)

        self.store.reap_monthly_active_users()

        self.reactor.advance(0)

        # We should be able to register more users
        token3 = self.create_user("kermit3")
        self.do_sync_for_user(token3)

    def test_trial_delay(self):
        self.hs.config.mau_trial_days = 1

        # We should be able to register more than the limit initially
        token1 = self.create_user("kermit1")
        self.do_sync_for_user(token1)
        token2 = self.create_user("kermit2")
        self.do_sync_for_user(token2)
        token3 = self.create_user("kermit3")
        self.do_sync_for_user(token3)

        # Advance time by 2 days
        self.reactor.advance(2 * 24 * 60 * 60)

        # Two users should be able to sync
        self.do_sync_for_user(token1)
        self.do_sync_for_user(token2)

        # But the third should fail
        with self.assertRaises(SynapseError) as cm:
            self.do_sync_for_user(token3)

        e = cm.exception
        self.assertEqual(e.code, 403)
        self.assertEqual(e.errcode, Codes.RESOURCE_LIMIT_EXCEEDED)

        # And new registrations are now denied too
        with self.assertRaises(SynapseError) as cm:
            self.create_user("kermit4")

        e = cm.exception
        self.assertEqual(e.code, 403)
        self.assertEqual(e.errcode, Codes.RESOURCE_LIMIT_EXCEEDED)

    def test_trial_users_cant_come_back(self):
        self.hs.config.mau_trial_days = 1

        # We should be able to register more than the limit initially
        token1 = self.create_user("kermit1")
        self.do_sync_for_user(token1)
        token2 = self.create_user("kermit2")
        self.do_sync_for_user(token2)
        token3 = self.create_user("kermit3")
        self.do_sync_for_user(token3)

        # Advance time by 2 days
        self.reactor.advance(2 * 24 * 60 * 60)

        # Two users should be able to sync
        self.do_sync_for_user(token1)
        self.do_sync_for_user(token2)

        # Advance by 2 months so everyone falls out of MAU
        self.reactor.advance(60 * 24 * 60 * 60)
        self.store.reap_monthly_active_users()
        self.reactor.advance(0)

        # We can create as many new users as we want
        token4 = self.create_user("kermit4")
        self.do_sync_for_user(token4)
        token5 = self.create_user("kermit5")
        self.do_sync_for_user(token5)
        token6 = self.create_user("kermit6")
        self.do_sync_for_user(token6)

        # users 2 and 3 can come back to bring us back up to MAU limit
        self.do_sync_for_user(token2)
        self.do_sync_for_user(token3)

        # New trial users can still sync
        self.do_sync_for_user(token4)
        self.do_sync_for_user(token5)
        self.do_sync_for_user(token6)

        # But old user cant
        with self.assertRaises(SynapseError) as cm:
            self.do_sync_for_user(token1)

        e = cm.exception
        self.assertEqual(e.code, 403)
        self.assertEqual(e.errcode, Codes.RESOURCE_LIMIT_EXCEEDED)

    def create_user(self, localpart):
        request_data = json.dumps(
            {
                "username": localpart,
                "password": "monkey",
                "auth": {"type": LoginType.DUMMY},
            }
        )

        request, channel = make_request("POST", "/register", request_data)
        render(request, self.resource, self.reactor)

        if channel.code != 200:
            raise HttpResponseException(
                channel.code, channel.result["reason"], channel.result["body"]
            ).to_synapse_error()

        access_token = channel.json_body["access_token"]

        return access_token

    def do_sync_for_user(self, token):
        request, channel = make_request(
            "GET", "/sync", access_token=token.encode('ascii')
        )
        render(request, self.resource, self.reactor)

        if channel.code != 200:
            raise HttpResponseException(
                channel.code, channel.result["reason"], channel.result["body"]
            ).to_synapse_error()
