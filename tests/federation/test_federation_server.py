# Copyright 2018 New Vector Ltd
# Copyright 2019 Matrix.org Federation C.I.C
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

from parameterized import parameterized

from twisted.test.proto_helpers import MemoryReactor

from synapse.api.room_versions import KNOWN_ROOM_VERSIONS
from synapse.config.server import DEFAULT_ROOM_VERSION
from synapse.crypto.event_signing import add_hashes_and_signatures
from synapse.events import make_event_from_dict
from synapse.federation.federation_server import server_matches_acl_event
from synapse.rest import admin
from synapse.rest.client import login, room
from synapse.server import HomeServer
from synapse.types import JsonDict
from synapse.util import Clock

from tests import unittest
from tests.unittest import override_config


class FederationServerTests(unittest.FederatingHomeserverTestCase):

    servlets = [
        admin.register_servlets,
        room.register_servlets,
        login.register_servlets,
    ]

    @parameterized.expand([(b"",), (b"foo",), (b'{"limit": Infinity}',)])
    def test_bad_request(self, query_content):
        """
        Querying with bad data returns a reasonable error code.
        """
        u1 = self.register_user("u1", "pass")
        u1_token = self.login("u1", "pass")

        room_1 = self.helper.create_room_as(u1, tok=u1_token)
        self.inject_room_member(room_1, "@user:other.example.com", "join")

        "/get_missing_events/(?P<room_id>[^/]*)/?"

        channel = self.make_request(
            "POST",
            "/_matrix/federation/v1/get_missing_events/%s" % (room_1,),
            query_content,
        )
        self.assertEqual(400, channel.code, channel.result)
        self.assertEqual(channel.json_body["errcode"], "M_NOT_JSON")


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

    def test_wildcard_matching(self):
        e = _create_acl_event({"allow": ["good*.com"]})
        self.assertTrue(
            server_matches_acl_event("good.com", e),
            "* matches 0 characters",
        )
        self.assertTrue(
            server_matches_acl_event("GOOD.COM", e),
            "pattern is case-insensitive",
        )
        self.assertTrue(
            server_matches_acl_event("good.aa.com", e),
            "* matches several characters, including '.'",
        )
        self.assertFalse(
            server_matches_acl_event("ishgood.com", e),
            "pattern does not allow prefixes",
        )


class StateQueryTests(unittest.FederatingHomeserverTestCase):
    servlets = [
        admin.register_servlets,
        room.register_servlets,
        login.register_servlets,
    ]

    def test_needs_to_be_in_room(self):
        """/v1/state/<room_id> requires the server to be in the room"""
        u1 = self.register_user("u1", "pass")
        u1_token = self.login("u1", "pass")

        room_1 = self.helper.create_room_as(u1, tok=u1_token)

        channel = self.make_signed_federation_request(
            "GET", "/_matrix/federation/v1/state/%s?event_id=xyz" % (room_1,)
        )
        self.assertEqual(403, channel.code, channel.result)
        self.assertEqual(channel.json_body["errcode"], "M_FORBIDDEN")


class SendJoinFederationTests(unittest.FederatingHomeserverTestCase):
    servlets = [
        admin.register_servlets,
        room.register_servlets,
        login.register_servlets,
    ]

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer):
        super().prepare(reactor, clock, hs)

        self._storage_controllers = hs.get_storage_controllers()

        # create the room
        creator_user_id = self.register_user("kermit", "test")
        tok = self.login("kermit", "test")
        self._room_id = self.helper.create_room_as(
            room_creator=creator_user_id, tok=tok
        )

        # a second member on the orgin HS
        second_member_user_id = self.register_user("fozzie", "bear")
        tok2 = self.login("fozzie", "bear")
        self.helper.join(self._room_id, second_member_user_id, tok=tok2)

    def _make_join(self, user_id) -> JsonDict:
        channel = self.make_signed_federation_request(
            "GET",
            f"/_matrix/federation/v1/make_join/{self._room_id}/{user_id}"
            f"?ver={DEFAULT_ROOM_VERSION}",
        )
        self.assertEqual(channel.code, 200, channel.json_body)
        return channel.json_body

    def test_send_join(self):
        """happy-path test of send_join"""
        joining_user = "@misspiggy:" + self.OTHER_SERVER_NAME
        join_result = self._make_join(joining_user)

        join_event_dict = join_result["event"]
        add_hashes_and_signatures(
            KNOWN_ROOM_VERSIONS[DEFAULT_ROOM_VERSION],
            join_event_dict,
            signature_name=self.OTHER_SERVER_NAME,
            signing_key=self.OTHER_SERVER_SIGNATURE_KEY,
        )
        channel = self.make_signed_federation_request(
            "PUT",
            f"/_matrix/federation/v2/send_join/{self._room_id}/x",
            content=join_event_dict,
        )
        self.assertEqual(channel.code, 200, channel.json_body)

        # we should get complete room state back
        returned_state = [
            (ev["type"], ev["state_key"]) for ev in channel.json_body["state"]
        ]
        self.assertCountEqual(
            returned_state,
            [
                ("m.room.create", ""),
                ("m.room.power_levels", ""),
                ("m.room.join_rules", ""),
                ("m.room.history_visibility", ""),
                ("m.room.member", "@kermit:test"),
                ("m.room.member", "@fozzie:test"),
                # nb: *not* the joining user
            ],
        )

        # also check the auth chain
        returned_auth_chain_events = [
            (ev["type"], ev["state_key"]) for ev in channel.json_body["auth_chain"]
        ]
        self.assertCountEqual(
            returned_auth_chain_events,
            [
                ("m.room.create", ""),
                ("m.room.member", "@kermit:test"),
                ("m.room.power_levels", ""),
                ("m.room.join_rules", ""),
            ],
        )

        # the room should show that the new user is a member
        r = self.get_success(
            self._storage_controllers.state.get_current_state(self._room_id)
        )
        self.assertEqual(r[("m.room.member", joining_user)].membership, "join")

    @override_config({"experimental_features": {"msc3706_enabled": True}})
    def test_send_join_partial_state(self):
        """When MSC3706 support is enabled, /send_join should return partial state"""
        joining_user = "@misspiggy:" + self.OTHER_SERVER_NAME
        join_result = self._make_join(joining_user)

        join_event_dict = join_result["event"]
        add_hashes_and_signatures(
            KNOWN_ROOM_VERSIONS[DEFAULT_ROOM_VERSION],
            join_event_dict,
            signature_name=self.OTHER_SERVER_NAME,
            signing_key=self.OTHER_SERVER_SIGNATURE_KEY,
        )
        channel = self.make_signed_federation_request(
            "PUT",
            f"/_matrix/federation/v2/send_join/{self._room_id}/x?org.matrix.msc3706.partial_state=true",
            content=join_event_dict,
        )
        self.assertEqual(channel.code, 200, channel.json_body)

        # expect a reduced room state
        returned_state = [
            (ev["type"], ev["state_key"]) for ev in channel.json_body["state"]
        ]
        self.assertCountEqual(
            returned_state,
            [
                ("m.room.create", ""),
                ("m.room.power_levels", ""),
                ("m.room.join_rules", ""),
                ("m.room.history_visibility", ""),
            ],
        )

        # the auth chain should not include anything already in "state"
        returned_auth_chain_events = [
            (ev["type"], ev["state_key"]) for ev in channel.json_body["auth_chain"]
        ]
        self.assertCountEqual(
            returned_auth_chain_events,
            [
                ("m.room.member", "@kermit:test"),
            ],
        )

        # the room should show that the new user is a member
        r = self.get_success(
            self._storage_controllers.state.get_current_state(self._room_id)
        )
        self.assertEqual(r[("m.room.member", joining_user)].membership, "join")


def _create_acl_event(content):
    return make_event_from_dict(
        {
            "room_id": "!a:b",
            "event_id": "$a:b",
            "type": "m.room.server_acls",
            "sender": "@a:b",
            "content": content,
        }
    )
