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

from mock import Mock

import synapse.rest.admin
from synapse.http.server import JsonResource
from synapse.rest.admin import VersionServlet
from synapse.rest.client.v1 import events, login, room
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
