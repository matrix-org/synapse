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

from mock import Mock

from synapse.rest.client.v2_alpha import sync

from tests import unittest


class FilterTestCase(unittest.HomeserverTestCase):

    user_id = "@apple:test"
    servlets = [sync.register_servlets]

    def make_homeserver(self, reactor, clock):

        hs = self.setup_test_homeserver(
            "red", http_client=None, federation_client=Mock()
        )
        return hs

    def test_sync_argless(self):
        request, channel = self.make_request("GET", "/sync")
        self.render(request)

        self.assertEqual(channel.code, 200)
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

    def test_sync_presence_disabled(self):
        """
        When presence is disabled, the key does not appear in /sync.
        """
        self.hs.config.use_presence = False

        request, channel = self.make_request("GET", "/sync")
        self.render(request)

        self.assertEqual(channel.code, 200)
        self.assertTrue(
            set(
                ["next_batch", "rooms", "account_data", "to_device", "device_lists"]
            ).issubset(set(channel.json_body.keys()))
        )
