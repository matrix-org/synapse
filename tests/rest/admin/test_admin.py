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
import urllib.parse
from typing import List, Optional

from mock import Mock

import synapse.rest.admin
from synapse.api.constants import UserTypes
from synapse.http.server import JsonResource
from synapse.rest.admin import VersionServlet
from synapse.rest.client.v1 import directory, events, login, room
from synapse.rest.client.v2_alpha import groups

from tests import unittest


class VersionTestCase(unittest.HomeserverTestCase):
    url = "/_synapse/admin/v1/server_version"

    def create_test_json_resource(self):
        resource = JsonResource(self.hs)
        VersionServlet(self.hs).register(resource)
        return resource

    def test_version_string(self):
        request, channel = self.make_request("GET", self.url, shorthand=False)
        self.render(request)

        self.assertEqual(200, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual(
            {"server_version", "python_version"}, set(channel.json_body.keys())
        )


class UserRegisterTestCase(unittest.HomeserverTestCase):

    servlets = [synapse.rest.admin.register_servlets_for_client_rest_resource]

    def make_homeserver(self, reactor, clock):

        self.url = "/_matrix/client/r0/admin/register"

        self.registration_handler = Mock()
        self.identity_handler = Mock()
        self.login_handler = Mock()
        self.device_handler = Mock()
        self.device_handler.check_device_registered = Mock(return_value="FAKE")

        self.datastore = Mock(return_value=Mock())
        self.datastore.get_current_state_deltas = Mock(return_value=(0, []))

        self.secrets = Mock()

        self.hs = self.setup_test_homeserver()

        self.hs.config.registration_shared_secret = "shared"

        self.hs.get_media_repository = Mock()
        self.hs.get_deactivate_account_handler = Mock()

        return self.hs

    def test_disabled(self):
        """
        If there is no shared secret, registration through this method will be
        prevented.
        """
        self.hs.config.registration_shared_secret = None

        request, channel = self.make_request("POST", self.url, b"{}")
        self.render(request)

        self.assertEqual(400, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual(
            "Shared secret registration is not enabled", channel.json_body["error"]
        )

    def test_get_nonce(self):
        """
        Calling GET on the endpoint will return a randomised nonce, using the
        homeserver's secrets provider.
        """
        secrets = Mock()
        secrets.token_hex = Mock(return_value="abcd")

        self.hs.get_secrets = Mock(return_value=secrets)

        request, channel = self.make_request("GET", self.url)
        self.render(request)

        self.assertEqual(channel.json_body, {"nonce": "abcd"})

    def test_expired_nonce(self):
        """
        Calling GET on the endpoint will return a randomised nonce, which will
        only last for SALT_TIMEOUT (60s).
        """
        request, channel = self.make_request("GET", self.url)
        self.render(request)
        nonce = channel.json_body["nonce"]

        # 59 seconds
        self.reactor.advance(59)

        body = json.dumps({"nonce": nonce})
        request, channel = self.make_request("POST", self.url, body.encode("utf8"))
        self.render(request)

        self.assertEqual(400, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual("username must be specified", channel.json_body["error"])

        # 61 seconds
        self.reactor.advance(2)

        request, channel = self.make_request("POST", self.url, body.encode("utf8"))
        self.render(request)

        self.assertEqual(400, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual("unrecognised nonce", channel.json_body["error"])

    def test_register_incorrect_nonce(self):
        """
        Only the provided nonce can be used, as it's checked in the MAC.
        """
        request, channel = self.make_request("GET", self.url)
        self.render(request)
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
        request, channel = self.make_request("POST", self.url, body.encode("utf8"))
        self.render(request)

        self.assertEqual(403, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual("HMAC incorrect", channel.json_body["error"])

    def test_register_correct_nonce(self):
        """
        When the correct nonce is provided, and the right key is provided, the
        user is registered.
        """
        request, channel = self.make_request("GET", self.url)
        self.render(request)
        nonce = channel.json_body["nonce"]

        want_mac = hmac.new(key=b"shared", digestmod=hashlib.sha1)
        want_mac.update(
            nonce.encode("ascii") + b"\x00bob\x00abc123\x00admin\x00support"
        )
        want_mac = want_mac.hexdigest()

        body = json.dumps(
            {
                "nonce": nonce,
                "username": "bob",
                "password": "abc123",
                "admin": True,
                "user_type": UserTypes.SUPPORT,
                "mac": want_mac,
            }
        )
        request, channel = self.make_request("POST", self.url, body.encode("utf8"))
        self.render(request)

        self.assertEqual(200, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual("@bob:test", channel.json_body["user_id"])

    def test_nonce_reuse(self):
        """
        A valid unrecognised nonce.
        """
        request, channel = self.make_request("GET", self.url)
        self.render(request)
        nonce = channel.json_body["nonce"]

        want_mac = hmac.new(key=b"shared", digestmod=hashlib.sha1)
        want_mac.update(nonce.encode("ascii") + b"\x00bob\x00abc123\x00admin")
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
        request, channel = self.make_request("POST", self.url, body.encode("utf8"))
        self.render(request)

        self.assertEqual(200, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual("@bob:test", channel.json_body["user_id"])

        # Now, try and reuse it
        request, channel = self.make_request("POST", self.url, body.encode("utf8"))
        self.render(request)

        self.assertEqual(400, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual("unrecognised nonce", channel.json_body["error"])

    def test_missing_parts(self):
        """
        Synapse will complain if you don't give nonce, username, password, and
        mac.  Admin and user_types are optional.  Additional checks are done for length
        and type.
        """

        def nonce():
            request, channel = self.make_request("GET", self.url)
            self.render(request)
            return channel.json_body["nonce"]

        #
        # Nonce check
        #

        # Must be present
        body = json.dumps({})
        request, channel = self.make_request("POST", self.url, body.encode("utf8"))
        self.render(request)

        self.assertEqual(400, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual("nonce must be specified", channel.json_body["error"])

        #
        # Username checks
        #

        # Must be present
        body = json.dumps({"nonce": nonce()})
        request, channel = self.make_request("POST", self.url, body.encode("utf8"))
        self.render(request)

        self.assertEqual(400, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual("username must be specified", channel.json_body["error"])

        # Must be a string
        body = json.dumps({"nonce": nonce(), "username": 1234})
        request, channel = self.make_request("POST", self.url, body.encode("utf8"))
        self.render(request)

        self.assertEqual(400, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual("Invalid username", channel.json_body["error"])

        # Must not have null bytes
        body = json.dumps({"nonce": nonce(), "username": "abcd\u0000"})
        request, channel = self.make_request("POST", self.url, body.encode("utf8"))
        self.render(request)

        self.assertEqual(400, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual("Invalid username", channel.json_body["error"])

        # Must not have null bytes
        body = json.dumps({"nonce": nonce(), "username": "a" * 1000})
        request, channel = self.make_request("POST", self.url, body.encode("utf8"))
        self.render(request)

        self.assertEqual(400, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual("Invalid username", channel.json_body["error"])

        #
        # Password checks
        #

        # Must be present
        body = json.dumps({"nonce": nonce(), "username": "a"})
        request, channel = self.make_request("POST", self.url, body.encode("utf8"))
        self.render(request)

        self.assertEqual(400, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual("password must be specified", channel.json_body["error"])

        # Must be a string
        body = json.dumps({"nonce": nonce(), "username": "a", "password": 1234})
        request, channel = self.make_request("POST", self.url, body.encode("utf8"))
        self.render(request)

        self.assertEqual(400, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual("Invalid password", channel.json_body["error"])

        # Must not have null bytes
        body = json.dumps({"nonce": nonce(), "username": "a", "password": "abcd\u0000"})
        request, channel = self.make_request("POST", self.url, body.encode("utf8"))
        self.render(request)

        self.assertEqual(400, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual("Invalid password", channel.json_body["error"])

        # Super long
        body = json.dumps({"nonce": nonce(), "username": "a", "password": "A" * 1000})
        request, channel = self.make_request("POST", self.url, body.encode("utf8"))
        self.render(request)

        self.assertEqual(400, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual("Invalid password", channel.json_body["error"])

        #
        # user_type check
        #

        # Invalid user_type
        body = json.dumps(
            {
                "nonce": nonce(),
                "username": "a",
                "password": "1234",
                "user_type": "invalid",
            }
        )
        request, channel = self.make_request("POST", self.url, body.encode("utf8"))
        self.render(request)

        self.assertEqual(400, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual("Invalid user type", channel.json_body["error"])


class ShutdownRoomTestCase(unittest.HomeserverTestCase):
    servlets = [
        synapse.rest.admin.register_servlets_for_client_rest_resource,
        login.register_servlets,
        events.register_servlets,
        room.register_servlets,
        room.register_deprecated_servlets,
    ]

    def prepare(self, reactor, clock, hs):
        self.event_creation_handler = hs.get_event_creation_handler()
        hs.config.user_consent_version = "1"

        consent_uri_builder = Mock()
        consent_uri_builder.build_user_consent_uri.return_value = "http://example.com"
        self.event_creation_handler._consent_uri_builder = consent_uri_builder

        self.store = hs.get_datastore()

        self.admin_user = self.register_user("admin", "pass", admin=True)
        self.admin_user_tok = self.login("admin", "pass")

        self.other_user = self.register_user("user", "pass")
        self.other_user_token = self.login("user", "pass")

        # Mark the admin user as having consented
        self.get_success(self.store.user_set_consent_version(self.admin_user, "1"))

    def test_shutdown_room_consent(self):
        """Test that we can shutdown rooms with local users who have not
        yet accepted the privacy policy. This used to fail when we tried to
        force part the user from the old room.
        """
        self.event_creation_handler._block_events_without_consent_error = None

        room_id = self.helper.create_room_as(self.other_user, tok=self.other_user_token)

        # Assert one user in room
        users_in_room = self.get_success(self.store.get_users_in_room(room_id))
        self.assertEqual([self.other_user], users_in_room)

        # Enable require consent to send events
        self.event_creation_handler._block_events_without_consent_error = "Error"

        # Assert that the user is getting consent error
        self.helper.send(
            room_id, body="foo", tok=self.other_user_token, expect_code=403
        )

        # Test that the admin can still send shutdown
        url = "admin/shutdown_room/" + room_id
        request, channel = self.make_request(
            "POST",
            url.encode("ascii"),
            json.dumps({"new_room_user_id": self.admin_user}),
            access_token=self.admin_user_tok,
        )
        self.render(request)

        self.assertEqual(200, int(channel.result["code"]), msg=channel.result["body"])

        # Assert there is now no longer anyone in the room
        users_in_room = self.get_success(self.store.get_users_in_room(room_id))
        self.assertEqual([], users_in_room)

    def test_shutdown_room_block_peek(self):
        """Test that a world_readable room can no longer be peeked into after
        it has been shut down.
        """

        self.event_creation_handler._block_events_without_consent_error = None

        room_id = self.helper.create_room_as(self.other_user, tok=self.other_user_token)

        # Enable world readable
        url = "rooms/%s/state/m.room.history_visibility" % (room_id,)
        request, channel = self.make_request(
            "PUT",
            url.encode("ascii"),
            json.dumps({"history_visibility": "world_readable"}),
            access_token=self.other_user_token,
        )
        self.render(request)
        self.assertEqual(200, int(channel.result["code"]), msg=channel.result["body"])

        # Test that the admin can still send shutdown
        url = "admin/shutdown_room/" + room_id
        request, channel = self.make_request(
            "POST",
            url.encode("ascii"),
            json.dumps({"new_room_user_id": self.admin_user}),
            access_token=self.admin_user_tok,
        )
        self.render(request)

        self.assertEqual(200, int(channel.result["code"]), msg=channel.result["body"])

        # Assert we can no longer peek into the room
        self._assert_peek(room_id, expect_code=403)

    def _assert_peek(self, room_id, expect_code):
        """Assert that the admin user can (or cannot) peek into the room.
        """

        url = "rooms/%s/initialSync" % (room_id,)
        request, channel = self.make_request(
            "GET", url.encode("ascii"), access_token=self.admin_user_tok
        )
        self.render(request)
        self.assertEqual(
            expect_code, int(channel.result["code"]), msg=channel.result["body"]
        )

        url = "events?timeout=0&room_id=" + room_id
        request, channel = self.make_request(
            "GET", url.encode("ascii"), access_token=self.admin_user_tok
        )
        self.render(request)
        self.assertEqual(
            expect_code, int(channel.result["code"]), msg=channel.result["body"]
        )


class DeleteGroupTestCase(unittest.HomeserverTestCase):
    servlets = [
        synapse.rest.admin.register_servlets_for_client_rest_resource,
        login.register_servlets,
        groups.register_servlets,
    ]

    def prepare(self, reactor, clock, hs):
        self.store = hs.get_datastore()

        self.admin_user = self.register_user("admin", "pass", admin=True)
        self.admin_user_tok = self.login("admin", "pass")

        self.other_user = self.register_user("user", "pass")
        self.other_user_token = self.login("user", "pass")

    def test_delete_group(self):
        # Create a new group
        request, channel = self.make_request(
            "POST",
            "/create_group".encode("ascii"),
            access_token=self.admin_user_tok,
            content={"localpart": "test"},
        )

        self.render(request)
        self.assertEqual(200, int(channel.result["code"]), msg=channel.result["body"])

        group_id = channel.json_body["group_id"]

        self._check_group(group_id, expect_code=200)

        # Invite/join another user

        url = "/groups/%s/admin/users/invite/%s" % (group_id, self.other_user)
        request, channel = self.make_request(
            "PUT", url.encode("ascii"), access_token=self.admin_user_tok, content={}
        )
        self.render(request)
        self.assertEqual(200, int(channel.result["code"]), msg=channel.result["body"])

        url = "/groups/%s/self/accept_invite" % (group_id,)
        request, channel = self.make_request(
            "PUT", url.encode("ascii"), access_token=self.other_user_token, content={}
        )
        self.render(request)
        self.assertEqual(200, int(channel.result["code"]), msg=channel.result["body"])

        # Check other user knows they're in the group
        self.assertIn(group_id, self._get_groups_user_is_in(self.admin_user_tok))
        self.assertIn(group_id, self._get_groups_user_is_in(self.other_user_token))

        # Now delete the group
        url = "/admin/delete_group/" + group_id
        request, channel = self.make_request(
            "POST",
            url.encode("ascii"),
            access_token=self.admin_user_tok,
            content={"localpart": "test"},
        )

        self.render(request)
        self.assertEqual(200, int(channel.result["code"]), msg=channel.result["body"])

        # Check group returns 404
        self._check_group(group_id, expect_code=404)

        # Check users don't think they're in the group
        self.assertNotIn(group_id, self._get_groups_user_is_in(self.admin_user_tok))
        self.assertNotIn(group_id, self._get_groups_user_is_in(self.other_user_token))

    def _check_group(self, group_id, expect_code):
        """Assert that trying to fetch the given group results in the given
        HTTP status code
        """

        url = "/groups/%s/profile" % (group_id,)
        request, channel = self.make_request(
            "GET", url.encode("ascii"), access_token=self.admin_user_tok
        )

        self.render(request)
        self.assertEqual(
            expect_code, int(channel.result["code"]), msg=channel.result["body"]
        )

    def _get_groups_user_is_in(self, access_token):
        """Returns the list of groups the user is in (given their access token)
        """
        request, channel = self.make_request(
            "GET", "/joined_groups".encode("ascii"), access_token=access_token
        )

        self.render(request)
        self.assertEqual(200, int(channel.result["code"]), msg=channel.result["body"])

        return channel.json_body["groups"]


class PurgeRoomTestCase(unittest.HomeserverTestCase):
    """Test /purge_room admin API.
    """

    servlets = [
        synapse.rest.admin.register_servlets,
        login.register_servlets,
        room.register_servlets,
    ]

    def prepare(self, reactor, clock, hs):
        self.store = hs.get_datastore()

        self.admin_user = self.register_user("admin", "pass", admin=True)
        self.admin_user_tok = self.login("admin", "pass")

    def test_purge_room(self):
        room_id = self.helper.create_room_as(self.admin_user, tok=self.admin_user_tok)

        # All users have to have left the room.
        self.helper.leave(room_id, user=self.admin_user, tok=self.admin_user_tok)

        url = "/_synapse/admin/v1/purge_room"
        request, channel = self.make_request(
            "POST",
            url.encode("ascii"),
            {"room_id": room_id},
            access_token=self.admin_user_tok,
        )
        self.render(request)

        self.assertEqual(200, int(channel.result["code"]), msg=channel.result["body"])

        # Test that the following tables have been purged of all rows related to the room.
        for table in (
            "current_state_events",
            "event_backward_extremities",
            "event_forward_extremities",
            "event_json",
            "event_push_actions",
            "event_search",
            "events",
            "group_rooms",
            "public_room_list_stream",
            "receipts_graph",
            "receipts_linearized",
            "room_aliases",
            "room_depth",
            "room_memberships",
            "room_stats_state",
            "room_stats_current",
            "room_stats_historical",
            "room_stats_earliest_token",
            "rooms",
            "stream_ordering_to_exterm",
            "users_in_public_rooms",
            "users_who_share_private_rooms",
            "appservice_room_list",
            "e2e_room_keys",
            "event_push_summary",
            "pusher_throttle",
            "group_summary_rooms",
            "local_invites",
            "room_account_data",
            "room_tags",
            "state_groups",
            "state_groups_state",
        ):
            count = self.get_success(
                self.store.db.simple_select_one_onecol(
                    table=table,
                    keyvalues={"room_id": room_id},
                    retcol="COUNT(*)",
                    desc="test_purge_room",
                )
            )

            self.assertEqual(count, 0, msg="Rows not purged in {}".format(table))

    test_purge_room.skip = "Disabled because it's currently broken"


class RoomTestCase(unittest.HomeserverTestCase):
    """Test /room admin API.
    """

    servlets = [
        synapse.rest.admin.register_servlets,
        login.register_servlets,
        room.register_servlets,
        directory.register_servlets,
    ]

    def prepare(self, reactor, clock, hs):
        self.store = hs.get_datastore()

        # Create user
        self.admin_user = self.register_user("user5", "pass", admin=True)
        self.admin_user_tok = self.login("user5", "pass")

    def test_list_rooms(self):
        """Test that we can list rooms"""
        # Create 3 test rooms
        total_rooms = 3
        room_ids = []
        for x in range(total_rooms):
            room_id = self.helper.create_room_as(
                self.admin_user, tok=self.admin_user_tok
            )
            room_ids.append(room_id)

        # Request the list of rooms
        url = "/_synapse/admin/v1/rooms"
        request, channel = self.make_request(
            "GET", url.encode("ascii"), access_token=self.admin_user_tok,
        )
        self.render(request)

        # Check request completed successfully
        self.assertEqual(200, int(channel.code), msg=channel.json_body)

        # Check that response json body contains a "rooms" key
        self.assertTrue(
            "rooms" in channel.json_body,
            msg="Response body does not " "contain a 'rooms' key",
        )

        # Check that 3 rooms were returned
        self.assertEqual(3, len(channel.json_body["rooms"]), msg=channel.json_body)

        # Check their room_ids match
        returned_room_ids = [room["room_id"] for room in channel.json_body["rooms"]]
        common_room_ids = set(room_ids) & set(returned_room_ids)
        self.assertEqual(
            len(common_room_ids),
            total_rooms,
            msg="Different room_ids than expected returned. "
            "Expected:\n%s\nReturned:\n%s" % (room_ids, returned_room_ids),
        )

        # Check that all fields are available
        for r in channel.json_body["rooms"]:
            self.assertIn("name", r)
            self.assertIn("canonical_alias", r)
            self.assertIn("joined_members", r)

        # We shouldn't receive a next token here as there's no further rooms to show
        self.assertTrue("next_token" not in channel.json_body)

    @unittest.DEBUG
    def test_list_rooms_pagination(self):
        """Test that we can get a full list of rooms through pagination"""
        # Create 5 test rooms
        total_rooms = 5
        room_ids = []
        for x in range(total_rooms):
            room_id = self.helper.create_room_as(
                self.admin_user, tok=self.admin_user_tok
            )
            room_ids.append(room_id)

        returned_room_ids = []

        # Request the list of rooms
        start = 0
        limit = 2

        run_count = 0
        should_repeat = True
        while should_repeat:
            run_count += 1

            url = "/_synapse/admin/v1/rooms?from=%d&limit=%d" % (start, limit)
            request, channel = self.make_request(
                "GET", url.encode("ascii"), access_token=self.admin_user_tok,
            )
            self.render(request)
            self.assertEqual(
                200, int(channel.result["code"]), msg=channel.result["body"]
            )

            self.assertTrue("rooms" in channel.json_body)
            for r in channel.json_body["rooms"]:
                returned_room_ids.append(r["room_id"])

            if "next_token" not in channel.json_body:
                # We have reached the end of the list
                should_repeat = False
            else:
                # Make another query with an updated start value
                start = channel.json_body["next_token"]

        # We should've queried the endpoint 3 times
        self.assertEqual(
            run_count,
            3,
            msg="Should've queried 3 times for 5 rooms with " "limit 2 per query",
        )

        # Check that we received all of the room ids
        common_room_ids = set(room_ids) & set(returned_room_ids)
        self.assertEqual(
            len(common_room_ids),
            total_rooms,
            msg="Different room_ids than expected returned. "
            "Expected:\n%s\nReturned:\n%s" % (room_ids, returned_room_ids),
        )

        url = "/_synapse/admin/v1/rooms?from=%d&limit=%d" % (start, limit)
        request, channel = self.make_request(
            "GET", url.encode("ascii"), access_token=self.admin_user_tok,
        )
        self.render(request)
        self.assertEqual(200, int(channel.result["code"]), msg=channel.result["body"])

    def test_correct_room_attributes(self):
        """Test the correct attributes for a room are returned"""
        # Create a test room
        room_id = self.helper.create_room_as(self.admin_user, tok=self.admin_user_tok)

        test_alias = "#test:test"
        test_room_name = "something"

        # Have another user join the room
        user_2 = self.register_user("user4", "pass")
        user_tok_2 = self.login("user4", "pass")
        self.helper.join(room_id, user_2, tok=user_tok_2)

        # Create a new alias to this room
        url = "/_matrix/client/r0/directory/room/%s" % (urllib.parse.quote(test_alias),)
        request, channel = self.make_request(
            "PUT",
            url.encode("ascii"),
            {"room_id": room_id},
            access_token=self.admin_user_tok,
        )
        self.render(request)
        self.assertEqual(200, int(channel.result["code"]), msg=channel.result["body"])

        # Set this new alias as the canonical alias for this room
        self.helper.send_state(
            room_id,
            "m.room.aliases",
            {"aliases": [test_alias]},
            tok=self.admin_user_tok,
            state_key="test",
        )
        self.helper.send_state(
            room_id,
            "m.room.canonical_alias",
            {"alias": test_alias},
            tok=self.admin_user_tok,
        )

        # Set a name for the room
        self.helper.send_state(
            room_id, "m.room.name", {"name": test_room_name}, tok=self.admin_user_tok,
        )

        # Request the list of rooms
        url = "/_synapse/admin/v1/rooms"
        request, channel = self.make_request(
            "GET", url.encode("ascii"), access_token=self.admin_user_tok,
        )
        self.render(request)
        self.assertEqual(200, int(channel.result["code"]), msg=channel.result["body"])

        # Check that rooms were returned
        self.assertTrue("rooms" in channel.json_body)
        rooms = channel.json_body["rooms"]

        # Check that only one room was returned
        self.assertEqual(len(rooms), 1)

        # Check that there is no `next_token`
        self.assertNotIn("next_token", channel.json_body)

        # Check that all provided attributes are set
        r = rooms[0]
        self.assertEqual(room_id, r["room_id"])
        self.assertEqual(test_room_name, r["name"])
        self.assertEqual(test_alias, r["canonical_alias"])

    def test_room_list_sort_order(self):
        """Test room list sort ordering. alphabetical versus number of members,
        reversing the order, etc.
        """
        # Create 3 test rooms
        room_id_1 = self.helper.create_room_as(self.admin_user, tok=self.admin_user_tok)
        room_id_2 = self.helper.create_room_as(self.admin_user, tok=self.admin_user_tok)
        room_id_3 = self.helper.create_room_as(self.admin_user, tok=self.admin_user_tok)

        # Set room names in alphabetical order. room 1 -> A, 2 -> B, 3 -> C
        self.helper.send_state(
            room_id_1, "m.room.name", {"name": "A"}, tok=self.admin_user_tok,
        )
        self.helper.send_state(
            room_id_2, "m.room.name", {"name": "B"}, tok=self.admin_user_tok,
        )
        self.helper.send_state(
            room_id_3, "m.room.name", {"name": "C"}, tok=self.admin_user_tok,
        )

        # Set room member size in the reverse order. room 1 -> 1 member, 2 -> 2, 3 -> 3
        user_1 = self.register_user("bob1", "pass")
        user_1_tok = self.login("bob1", "pass")
        self.helper.join(room_id_2, user_1, tok=user_1_tok)

        user_2 = self.register_user("bob2", "pass")
        user_2_tok = self.login("bob2", "pass")
        self.helper.join(room_id_3, user_2, tok=user_2_tok)

        user_3 = self.register_user("bob3", "pass")
        user_3_tok = self.login("bob3", "pass")
        self.helper.join(room_id_3, user_3, tok=user_3_tok)

        def _order_test(
            order_type: str, expected_room_list: List[str], reverse: bool = False,
        ):
            """Request the list of rooms in a certain order. Assert that order is what
            we expect

            Args:
                order_type: The type of ordering to give the server
                expected_room_list: The list of room_ids in the order we expect to get
                    back from the server
            """
            # Request the list of rooms in the given order
            url = "/_synapse/admin/v1/rooms?order_by=%s" % (order_type,)
            if reverse:
                url += "&dir=b"
            request, channel = self.make_request(
                "GET", url.encode("ascii"), access_token=self.admin_user_tok,
            )
            self.render(request)
            self.assertEqual(200, channel.code, msg=channel.json_body)

            # Check that rooms were returned
            self.assertTrue("rooms" in channel.json_body)
            rooms = channel.json_body["rooms"]

            # Check that rooms were returned in alphabetical order
            returned_order = [r["room_id"] for r in rooms]
            self.assertListEqual(expected_room_list, returned_order)  # order is checked

        # Test different sort orders, with forward and reverse directions
        _order_test("alphabetical", [room_id_1, room_id_2, room_id_3])
        _order_test("alphabetical", [room_id_3, room_id_2, room_id_1], reverse=True)

        _order_test("size", [room_id_3, room_id_2, room_id_1])
        _order_test("size", [room_id_1, room_id_2, room_id_3], reverse=True)

    def test_search_term(self):
        """Test that searching for a room works correctly"""
        # Create two test rooms
        room_id_1 = self.helper.create_room_as(self.admin_user, tok=self.admin_user_tok)
        room_id_2 = self.helper.create_room_as(self.admin_user, tok=self.admin_user_tok)

        room_name_1 = "something"
        room_name_2 = "else"

        # Set the name for each room
        self.helper.send_state(
            room_id_1, "m.room.name", {"name": room_name_1}, tok=self.admin_user_tok,
        )
        self.helper.send_state(
            room_id_2, "m.room.name", {"name": room_name_2}, tok=self.admin_user_tok,
        )

        def _search_test(
            expected_room_id: Optional[str],
            search_term: str,
            expected_http_code: int = 200,
        ):
            """Search for a room and check that the returned room's id is a match

            Args:
                expected_room_id: The room_id expected to be returned by the API. Set
                    to None to expect zero results for the search
                search_term: The term to search for room names with
                expected_http_code: The expected http code for the request
            """
            url = "/_synapse/admin/v1/rooms?search_term=%s" % (search_term,)
            request, channel = self.make_request(
                "GET", url.encode("ascii"), access_token=self.admin_user_tok,
            )
            self.render(request)
            self.assertEqual(expected_http_code, channel.code, msg=channel.json_body)

            if expected_http_code != 200:
                return

            # Check that rooms were returned
            self.assertTrue("rooms" in channel.json_body)
            rooms = channel.json_body["rooms"]

            # Check that the expected number of rooms were returned
            self.assertEqual(len(rooms), 1 if expected_room_id else 0)

            if expected_room_id:
                # Check that the first returned room id is correct
                r = rooms[0]
                self.assertEqual(expected_room_id, r["room_id"])

        # Perform search tests
        _search_test(room_id_1, "something")
        _search_test(room_id_1, "thing")

        _search_test(room_id_2, "else")
        _search_test(room_id_2, "se")

        _search_test(None, "foo")
        _search_test(None, "bar")
        _search_test(None, "", expected_http_code=400)
