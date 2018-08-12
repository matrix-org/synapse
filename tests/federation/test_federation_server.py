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
import logging

from synapse.events import FrozenEvent
from synapse.federation.federation_server import server_matches_acl_event

from tests import unittest


@unittest.DEBUG
class ServerACLsTestCase(unittest.TestCase):
    def test_blacklisted_server(self):
        e = _create_acl_event({"allow": ["*"], "deny": ["evil.com"]})
        logging.info("ACL event: %s", e.content)

        self.assertFalse(server_matches_acl_event("evil.com", e))
        self.assertFalse(server_matches_acl_event("EVIL.COM", e))

        self.assertTrue(server_matches_acl_event("evil.com.au", e))
        self.assertTrue(server_matches_acl_event("honestly.not.evil.com", e))

    def test_block_ip_literals(self):
        e = _create_acl_event({"allow_ip_literals": False, "allow": ["*"]})
        logging.info("ACL event: %s", e.content)

        self.assertFalse(server_matches_acl_event("1.2.3.4", e))
        self.assertTrue(server_matches_acl_event("1a.2.3.4", e))
        self.assertFalse(server_matches_acl_event("[1:2::]", e))
        self.assertTrue(server_matches_acl_event("1:2:3:4", e))


def _create_acl_event(content):
    return FrozenEvent(
        {
            "room_id": "!a:b",
            "event_id": "$a:b",
            "type": "m.room.server_acls",
            "sender": "@a:b",
            "content": content,
        }
    )
