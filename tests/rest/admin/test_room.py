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

import json
import os
import urllib.parse
from binascii import unhexlify
from typing import List, Optional

from mock import Mock

from twisted.internet.defer import Deferred

import synapse.rest.admin
from synapse.http.server import JsonResource
from synapse.logging.context import make_deferred_yieldable
from synapse.rest.admin import VersionServlet
from synapse.rest.client.v1 import directory, events, login, room
from synapse.rest.client.v2_alpha import groups

from tests import unittest


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
            # "state_groups",  # Current impl leaves orphaned state groups around.
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
        self.admin_user = self.register_user("admin", "pass", admin=True)
        self.admin_user_tok = self.login("admin", "pass")

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
        self.assertEqual(room_ids, returned_room_ids)

        # Check that all fields are available
        for r in channel.json_body["rooms"]:
            self.assertIn("name", r)
            self.assertIn("canonical_alias", r)
            self.assertIn("joined_members", r)
            self.assertIn("joined_local_members", r)
            self.assertIn("version", r)
            self.assertIn("creator", r)
            self.assertIn("encryption", r)
            self.assertIn("is_federatable", r)
            self.assertIn("is_public", r)
            self.assertIn("join_rules", r)
            self.assertIn("guest_access", r)
            self.assertIn("history_visibility", r)
            self.assertIn("state_events", r)

        # Check that the correct number of total rooms was returned
        self.assertEqual(channel.json_body["total_rooms"], total_rooms)

        # Check that the offset is correct
        # Should be 0 as we aren't paginating
        self.assertEqual(channel.json_body["offset"], 0)

        # Check that the prev_batch parameter is not present
        self.assertNotIn("prev_batch", channel.json_body)

        # We shouldn't receive a next token here as there's no further rooms to show
        self.assertNotIn("next_batch", channel.json_body)

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

        # Set the name of the rooms so we get a consistent returned ordering
        for idx, room_id in enumerate(room_ids):
            self.helper.send_state(
                room_id, "m.room.name", {"name": str(idx)}, tok=self.admin_user_tok,
            )

        # Request the list of rooms
        returned_room_ids = []
        start = 0
        limit = 2

        run_count = 0
        should_repeat = True
        while should_repeat:
            run_count += 1

            url = "/_synapse/admin/v1/rooms?from=%d&limit=%d&order_by=%s" % (
                start,
                limit,
                "alphabetical",
            )
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

            # Check that the correct number of total rooms was returned
            self.assertEqual(channel.json_body["total_rooms"], total_rooms)

            # Check that the offset is correct
            # We're only getting 2 rooms each page, so should be 2 * last run_count
            self.assertEqual(channel.json_body["offset"], 2 * (run_count - 1))

            if run_count > 1:
                # Check the value of prev_batch is correct
                self.assertEqual(channel.json_body["prev_batch"], 2 * (run_count - 2))

            if "next_batch" not in channel.json_body:
                # We have reached the end of the list
                should_repeat = False
            else:
                # Make another query with an updated start value
                start = channel.json_body["next_batch"]

        # We should've queried the endpoint 3 times
        self.assertEqual(
            run_count,
            3,
            msg="Should've queried 3 times for 5 rooms with limit 2 per query",
        )

        # Check that we received all of the room ids
        self.assertEqual(room_ids, returned_room_ids)

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

        # And that the value of the total_rooms key was correct
        self.assertEqual(channel.json_body["total_rooms"], 1)

        # Check that the offset is correct
        # We're not paginating, so should be 0
        self.assertEqual(channel.json_body["offset"], 0)

        # Check that there is no `prev_batch`
        self.assertNotIn("prev_batch", channel.json_body)

        # Check that there is no `next_batch`
        self.assertNotIn("next_batch", channel.json_body)

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

            # Check for the correct total_rooms value
            self.assertEqual(channel.json_body["total_rooms"], 3)

            # Check that the offset is correct
            # We're not paginating, so should be 0
            self.assertEqual(channel.json_body["offset"], 0)

            # Check that there is no `prev_batch`
            self.assertNotIn("prev_batch", channel.json_body)

            # Check that there is no `next_batch`
            self.assertNotIn("next_batch", channel.json_body)

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
            expected_room_count = 1 if expected_room_id else 0
            self.assertEqual(len(rooms), expected_room_count)
            self.assertEqual(channel.json_body["total_rooms"], expected_room_count)

            # Check that the offset is correct
            # We're not paginating, so should be 0
            self.assertEqual(channel.json_body["offset"], 0)

            # Check that there is no `prev_batch`
            self.assertNotIn("prev_batch", channel.json_body)

            # Check that there is no `next_batch`
            self.assertNotIn("next_batch", channel.json_body)

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
