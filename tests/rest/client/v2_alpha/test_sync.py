# -*- coding: utf-8 -*-
# Copyright 2018 New Vector
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

import synapse.types
from synapse.http.server import JsonResource
from synapse.rest.client.v2_alpha import sync
from synapse.types import UserID
from synapse.util import Clock

from tests import unittest
from tests.server import ThreadedMemoryReactorClock as MemoryReactorClock
from tests.server import make_request, setup_test_homeserver, wait_until_result

PATH_PREFIX = "/_matrix/client/v2_alpha"


class FilterTestCase(unittest.TestCase):

    USER_ID = b"@apple:test"
    TO_REGISTER = [sync]

    def setUp(self):
        self.clock = MemoryReactorClock()
        self.hs_clock = Clock(self.clock)

        self.hs = setup_test_homeserver(
            http_client=None, clock=self.hs_clock, reactor=self.clock
        )

        self.auth = self.hs.get_auth()

        def get_user_by_access_token(token=None, allow_guest=False):
            return {
                "user": UserID.from_string(self.USER_ID),
                "token_id": 1,
                "is_guest": False,
            }

        def get_user_by_req(request, allow_guest=False, rights="access"):
            return synapse.types.create_requester(
                UserID.from_string(self.USER_ID), 1, False, None
            )

        self.auth.get_user_by_access_token = get_user_by_access_token
        self.auth.get_user_by_req = get_user_by_req

        self.store = self.hs.get_datastore()
        self.filtering = self.hs.get_filtering()
        self.resource = JsonResource(self.hs)

        for r in self.TO_REGISTER:
            r.register_servlets(self.hs, self.resource)

    def test_sync_argless(self):
        request, channel = make_request(b"GET", b"/_matrix/client/r0/sync")
        request.render(self.resource)
        wait_until_result(self.clock, channel)

        self.assertEqual(channel.result["code"], b"200")
        self.assertTrue(
            set(
                [
                    "next_batch",
                    "rooms",
                    "presence",
                    "account_data",
                    "to_device",
                    "device_lists",
                ]
            ).issubset(set(channel.json_body.keys()))
        )
