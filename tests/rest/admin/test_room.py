# Copyright 2020 Dirk Klimpel
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
import time
import urllib.parse
from typing import List, Optional
from unittest.mock import Mock

from parameterized import parameterized

from twisted.test.proto_helpers import MemoryReactor

import synapse.rest.admin
from synapse.api.constants import EventTypes, Membership, RoomTypes
from synapse.api.errors import Codes
from synapse.handlers.pagination import PaginationHandler, PurgeStatus
from synapse.rest.client import directory, events, login, room
from synapse.server import HomeServer
from synapse.util import Clock
from synapse.util.stringutils import random_string

from tests import unittest

"""Tests admin REST events for /rooms paths."""


class DeleteRoomTestCase(unittest.HomeserverTestCase):
    servlets = [
        synapse.rest.admin.register_servlets,
        login.register_servlets,
        events.register_servlets,
        room.register_servlets,
        room.register_deprecated_servlets,
    ]

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self.event_creation_handler = hs.get_event_creation_handler()
        hs.config.consent.user_consent_version = "1"

        consent_uri_builder = Mock()
        consent_uri_builder.build_user_consent_uri.return_value = "http://example.com"
        self.event_creation_handler._consent_uri_builder = consent_uri_builder

        self.store = hs.get_datastores().main

        self.admin_user = self.register_user("admin", "pass", admin=True)
        self.admin_user_tok = self.login("admin", "pass")

        self.other_user = self.register_user("user", "pass")
        self.other_user_tok = self.login("user", "pass")

        # Mark the admin user as having consented
        self.get_success(self.store.user_set_consent_version(self.admin_user, "1"))

        self.room_id = self.helper.create_room_as(
            self.other_user, tok=self.other_user_tok
        )
        self.url = "/_synapse/admin/v1/rooms/%s" % self.room_id

    def test_requester_is_no_admin(self) -> None:
        """
        If the user is not a server admin, an error 403 is returned.
        """

        channel = self.make_request(
            "DELETE",
            self.url,
            {},
            access_token=self.other_user_tok,
        )

        self.assertEqual(403, channel.code, msg=channel.json_body)
        self.assertEqual(Codes.FORBIDDEN, channel.json_body["errcode"])

    def test_room_does_not_exist(self) -> None:
        """
        Check that unknown rooms/server return 200
        """
        url = "/_synapse/admin/v1/rooms/%s" % "!unknown:test"

        channel = self.make_request(
            "DELETE",
            url,
            {},
            access_token=self.admin_user_tok,
        )

        self.assertEqual(200, channel.code, msg=channel.json_body)

    def test_room_is_not_valid(self) -> None:
        """
        Check that invalid room names, return an error 400.
        """
        url = "/_synapse/admin/v1/rooms/%s" % "invalidroom"

        channel = self.make_request(
            "DELETE",
            url,
            {},
            access_token=self.admin_user_tok,
        )

        self.assertEqual(400, channel.code, msg=channel.json_body)
        self.assertEqual(
            "invalidroom is not a legal room ID",
            channel.json_body["error"],
        )

    def test_new_room_user_does_not_exist(self) -> None:
        """
        Tests that the user ID must be from local server but it does not have to exist.
        """

        channel = self.make_request(
            "DELETE",
            self.url,
            content={"new_room_user_id": "@unknown:test"},
            access_token=self.admin_user_tok,
        )

        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertIn("new_room_id", channel.json_body)
        self.assertIn("kicked_users", channel.json_body)
        self.assertIn("failed_to_kick_users", channel.json_body)
        self.assertIn("local_aliases", channel.json_body)

    def test_new_room_user_is_not_local(self) -> None:
        """
        Check that only local users can create new room to move members.
        """

        channel = self.make_request(
            "DELETE",
            self.url,
            content={"new_room_user_id": "@not:exist.bla"},
            access_token=self.admin_user_tok,
        )

        self.assertEqual(400, channel.code, msg=channel.json_body)
        self.assertEqual(
            "User must be our own: @not:exist.bla",
            channel.json_body["error"],
        )

    def test_block_is_not_bool(self) -> None:
        """
        If parameter `block` is not boolean, return an error
        """

        channel = self.make_request(
            "DELETE",
            self.url,
            content={"block": "NotBool"},
            access_token=self.admin_user_tok,
        )

        self.assertEqual(400, channel.code, msg=channel.json_body)
        self.assertEqual(Codes.BAD_JSON, channel.json_body["errcode"])

    def test_purge_is_not_bool(self) -> None:
        """
        If parameter `purge` is not boolean, return an error
        """

        channel = self.make_request(
            "DELETE",
            self.url,
            content={"purge": "NotBool"},
            access_token=self.admin_user_tok,
        )

        self.assertEqual(400, channel.code, msg=channel.json_body)
        self.assertEqual(Codes.BAD_JSON, channel.json_body["errcode"])

    def test_purge_room_and_block(self) -> None:
        """Test to purge a room and block it.
        Members will not be moved to a new room and will not receive a message.
        """
        # Test that room is not purged
        with self.assertRaises(AssertionError):
            self._is_purged(self.room_id)

        # Test that room is not blocked
        self._is_blocked(self.room_id, expect=False)

        # Assert one user in room
        self._is_member(room_id=self.room_id, user_id=self.other_user)

        channel = self.make_request(
            "DELETE",
            self.url.encode("ascii"),
            content={"block": True, "purge": True},
            access_token=self.admin_user_tok,
        )

        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual(None, channel.json_body["new_room_id"])
        self.assertEqual(self.other_user, channel.json_body["kicked_users"][0])
        self.assertIn("failed_to_kick_users", channel.json_body)
        self.assertIn("local_aliases", channel.json_body)

        self._is_purged(self.room_id)
        self._is_blocked(self.room_id, expect=True)
        self._has_no_members(self.room_id)

    def test_purge_room_and_not_block(self) -> None:
        """Test to purge a room and do not block it.
        Members will not be moved to a new room and will not receive a message.
        """
        # Test that room is not purged
        with self.assertRaises(AssertionError):
            self._is_purged(self.room_id)

        # Test that room is not blocked
        self._is_blocked(self.room_id, expect=False)

        # Assert one user in room
        self._is_member(room_id=self.room_id, user_id=self.other_user)

        channel = self.make_request(
            "DELETE",
            self.url.encode("ascii"),
            content={"block": False, "purge": True},
            access_token=self.admin_user_tok,
        )

        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual(None, channel.json_body["new_room_id"])
        self.assertEqual(self.other_user, channel.json_body["kicked_users"][0])
        self.assertIn("failed_to_kick_users", channel.json_body)
        self.assertIn("local_aliases", channel.json_body)

        self._is_purged(self.room_id)
        self._is_blocked(self.room_id, expect=False)
        self._has_no_members(self.room_id)

    def test_block_room_and_not_purge(self) -> None:
        """Test to block a room without purging it.
        Members will not be moved to a new room and will not receive a message.
        The room will not be purged.
        """
        # Test that room is not purged
        with self.assertRaises(AssertionError):
            self._is_purged(self.room_id)

        # Test that room is not blocked
        self._is_blocked(self.room_id, expect=False)

        # Assert one user in room
        self._is_member(room_id=self.room_id, user_id=self.other_user)

        channel = self.make_request(
            "DELETE",
            self.url.encode("ascii"),
            content={"block": True, "purge": False},
            access_token=self.admin_user_tok,
        )

        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual(None, channel.json_body["new_room_id"])
        self.assertEqual(self.other_user, channel.json_body["kicked_users"][0])
        self.assertIn("failed_to_kick_users", channel.json_body)
        self.assertIn("local_aliases", channel.json_body)

        with self.assertRaises(AssertionError):
            self._is_purged(self.room_id)
        self._is_blocked(self.room_id, expect=True)
        self._has_no_members(self.room_id)

    @parameterized.expand([(True,), (False,)])
    def test_block_unknown_room(self, purge: bool) -> None:
        """
        We can block an unknown room. In this case, the `purge` argument
        should be ignored.
        """
        room_id = "!unknown:test"

        # The room isn't already in the blocked rooms table
        self._is_blocked(room_id, expect=False)

        # Request the room be blocked.
        channel = self.make_request(
            "DELETE",
            f"/_synapse/admin/v1/rooms/{room_id}",
            {"block": True, "purge": purge},
            access_token=self.admin_user_tok,
        )

        # The room is now blocked.
        self.assertEqual(200, channel.code, msg=channel.json_body)
        self._is_blocked(room_id)

    def test_shutdown_room_consent(self) -> None:
        """Test that we can shutdown rooms with local users who have not
        yet accepted the privacy policy. This used to fail when we tried to
        force part the user from the old room.
        Members will be moved to a new room and will receive a message.
        """
        self.event_creation_handler._block_events_without_consent_error = None

        # Assert one user in room
        users_in_room = self.get_success(self.store.get_users_in_room(self.room_id))
        self.assertEqual([self.other_user], users_in_room)

        # Enable require consent to send events
        self.event_creation_handler._block_events_without_consent_error = "Error"

        # Assert that the user is getting consent error
        self.helper.send(
            self.room_id,
            body="foo",
            tok=self.other_user_tok,
            expect_code=403,
        )

        # Test that room is not purged
        with self.assertRaises(AssertionError):
            self._is_purged(self.room_id)

        # Assert one user in room
        self._is_member(room_id=self.room_id, user_id=self.other_user)

        # Test that the admin can still send shutdown
        channel = self.make_request(
            "DELETE",
            self.url,
            {"new_room_user_id": self.admin_user},
            access_token=self.admin_user_tok,
        )

        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual(self.other_user, channel.json_body["kicked_users"][0])
        self.assertIn("new_room_id", channel.json_body)
        self.assertIn("failed_to_kick_users", channel.json_body)
        self.assertIn("local_aliases", channel.json_body)

        # Test that member has moved to new room
        self._is_member(
            room_id=channel.json_body["new_room_id"], user_id=self.other_user
        )

        self._is_purged(self.room_id)
        self._has_no_members(self.room_id)

    def test_shutdown_room_block_peek(self) -> None:
        """Test that a world_readable room can no longer be peeked into after
        it has been shut down.
        Members will be moved to a new room and will receive a message.
        """
        self.event_creation_handler._block_events_without_consent_error = None

        # Enable world readable
        url = "rooms/%s/state/m.room.history_visibility" % (self.room_id,)
        channel = self.make_request(
            "PUT",
            url.encode("ascii"),
            {"history_visibility": "world_readable"},
            access_token=self.other_user_tok,
        )
        self.assertEqual(200, channel.code, msg=channel.json_body)

        # Test that room is not purged
        with self.assertRaises(AssertionError):
            self._is_purged(self.room_id)

        # Assert one user in room
        self._is_member(room_id=self.room_id, user_id=self.other_user)

        # Test that the admin can still send shutdown
        channel = self.make_request(
            "DELETE",
            self.url,
            {"new_room_user_id": self.admin_user},
            access_token=self.admin_user_tok,
        )

        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual(self.other_user, channel.json_body["kicked_users"][0])
        self.assertIn("new_room_id", channel.json_body)
        self.assertIn("failed_to_kick_users", channel.json_body)
        self.assertIn("local_aliases", channel.json_body)

        # Test that member has moved to new room
        self._is_member(
            room_id=channel.json_body["new_room_id"], user_id=self.other_user
        )

        self._is_purged(self.room_id)
        self._has_no_members(self.room_id)

        # Assert we can no longer peek into the room
        self._assert_peek(self.room_id, expect_code=403)

    def _is_blocked(self, room_id: str, expect: bool = True) -> None:
        """Assert that the room is blocked or not"""
        d = self.store.is_room_blocked(room_id)
        if expect:
            self.assertTrue(self.get_success(d))
        else:
            self.assertIsNone(self.get_success(d))

    def _has_no_members(self, room_id: str) -> None:
        """Assert there is now no longer anyone in the room"""
        users_in_room = self.get_success(self.store.get_users_in_room(room_id))
        self.assertEqual([], users_in_room)

    def _is_member(self, room_id: str, user_id: str) -> None:
        """Test that user is member of the room"""
        users_in_room = self.get_success(self.store.get_users_in_room(room_id))
        self.assertIn(user_id, users_in_room)

    def _is_purged(self, room_id: str) -> None:
        """Test that the following tables have been purged of all rows related to the room."""
        for table in PURGE_TABLES:
            count = self.get_success(
                self.store.db_pool.simple_select_one_onecol(
                    table=table,
                    keyvalues={"room_id": room_id},
                    retcol="COUNT(*)",
                    desc="test_purge_room",
                )
            )

            self.assertEqual(count, 0, msg=f"Rows not purged in {table}")

    def _assert_peek(self, room_id: str, expect_code: int) -> None:
        """Assert that the admin user can (or cannot) peek into the room."""

        url = "rooms/%s/initialSync" % (room_id,)
        channel = self.make_request(
            "GET", url.encode("ascii"), access_token=self.admin_user_tok
        )
        self.assertEqual(expect_code, channel.code, msg=channel.json_body)

        url = "events?timeout=0&room_id=" + room_id
        channel = self.make_request(
            "GET", url.encode("ascii"), access_token=self.admin_user_tok
        )
        self.assertEqual(expect_code, channel.code, msg=channel.json_body)


class DeleteRoomV2TestCase(unittest.HomeserverTestCase):
    servlets = [
        synapse.rest.admin.register_servlets,
        login.register_servlets,
        events.register_servlets,
        room.register_servlets,
        room.register_deprecated_servlets,
    ]

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self.event_creation_handler = hs.get_event_creation_handler()
        hs.config.consent.user_consent_version = "1"

        consent_uri_builder = Mock()
        consent_uri_builder.build_user_consent_uri.return_value = "http://example.com"
        self.event_creation_handler._consent_uri_builder = consent_uri_builder

        self.store = hs.get_datastores().main

        self.admin_user = self.register_user("admin", "pass", admin=True)
        self.admin_user_tok = self.login("admin", "pass")

        self.other_user = self.register_user("user", "pass")
        self.other_user_tok = self.login("user", "pass")

        # Mark the admin user as having consented
        self.get_success(self.store.user_set_consent_version(self.admin_user, "1"))

        self.room_id = self.helper.create_room_as(
            self.other_user, tok=self.other_user_tok
        )
        self.url = f"/_synapse/admin/v2/rooms/{self.room_id}"
        self.url_status_by_room_id = (
            f"/_synapse/admin/v2/rooms/{self.room_id}/delete_status"
        )
        self.url_status_by_delete_id = "/_synapse/admin/v2/rooms/delete_status/"

    @parameterized.expand(
        [
            ("DELETE", "/_synapse/admin/v2/rooms/%s"),
            ("GET", "/_synapse/admin/v2/rooms/%s/delete_status"),
            ("GET", "/_synapse/admin/v2/rooms/delete_status/%s"),
        ]
    )
    def test_requester_is_no_admin(self, method: str, url: str) -> None:
        """
        If the user is not a server admin, an error 403 is returned.
        """

        channel = self.make_request(
            method,
            url % self.room_id,
            content={},
            access_token=self.other_user_tok,
        )

        self.assertEqual(403, channel.code, msg=channel.json_body)
        self.assertEqual(Codes.FORBIDDEN, channel.json_body["errcode"])

    def test_room_does_not_exist(self) -> None:
        """
        Check that unknown rooms/server return 200

        This is important, as it allows incomplete vestiges of rooms to be cleared up
        even if the create event/etc is missing.
        """
        room_id = "!unknown:test"
        channel = self.make_request(
            "DELETE",
            f"/_synapse/admin/v2/rooms/{room_id}",
            content={},
            access_token=self.admin_user_tok,
        )

        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertIn("delete_id", channel.json_body)
        delete_id = channel.json_body["delete_id"]

        # get status
        channel = self.make_request(
            "GET",
            f"/_synapse/admin/v2/rooms/{room_id}/delete_status",
            access_token=self.admin_user_tok,
        )

        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual(1, len(channel.json_body["results"]))
        self.assertEqual("complete", channel.json_body["results"][0]["status"])
        self.assertEqual(delete_id, channel.json_body["results"][0]["delete_id"])

    @parameterized.expand(
        [
            ("DELETE", "/_synapse/admin/v2/rooms/%s"),
            ("GET", "/_synapse/admin/v2/rooms/%s/delete_status"),
        ]
    )
    def test_room_is_not_valid(self, method: str, url: str) -> None:
        """
        Check that invalid room names, return an error 400.
        """

        channel = self.make_request(
            method,
            url % "invalidroom",
            content={},
            access_token=self.admin_user_tok,
        )

        self.assertEqual(400, channel.code, msg=channel.json_body)
        self.assertEqual(
            "invalidroom is not a legal room ID",
            channel.json_body["error"],
        )

    def test_new_room_user_does_not_exist(self) -> None:
        """
        Tests that the user ID must be from local server but it does not have to exist.
        """

        channel = self.make_request(
            "DELETE",
            self.url,
            content={"new_room_user_id": "@unknown:test"},
            access_token=self.admin_user_tok,
        )

        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertIn("delete_id", channel.json_body)
        delete_id = channel.json_body["delete_id"]

        self._test_result(delete_id, self.other_user, expect_new_room=True)

    def test_new_room_user_is_not_local(self) -> None:
        """
        Check that only local users can create new room to move members.
        """

        channel = self.make_request(
            "DELETE",
            self.url,
            content={"new_room_user_id": "@not:exist.bla"},
            access_token=self.admin_user_tok,
        )

        self.assertEqual(400, channel.code, msg=channel.json_body)
        self.assertEqual(
            "User must be our own: @not:exist.bla",
            channel.json_body["error"],
        )

    def test_block_is_not_bool(self) -> None:
        """
        If parameter `block` is not boolean, return an error
        """

        channel = self.make_request(
            "DELETE",
            self.url,
            content={"block": "NotBool"},
            access_token=self.admin_user_tok,
        )

        self.assertEqual(400, channel.code, msg=channel.json_body)
        self.assertEqual(Codes.BAD_JSON, channel.json_body["errcode"])

    def test_purge_is_not_bool(self) -> None:
        """
        If parameter `purge` is not boolean, return an error
        """

        channel = self.make_request(
            "DELETE",
            self.url,
            content={"purge": "NotBool"},
            access_token=self.admin_user_tok,
        )

        self.assertEqual(400, channel.code, msg=channel.json_body)
        self.assertEqual(Codes.BAD_JSON, channel.json_body["errcode"])

    def test_delete_expired_status(self) -> None:
        """Test that the task status is removed after expiration."""

        # first task, do not purge, that we can create a second task
        channel = self.make_request(
            "DELETE",
            self.url.encode("ascii"),
            content={"purge": False},
            access_token=self.admin_user_tok,
        )

        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertIn("delete_id", channel.json_body)
        delete_id1 = channel.json_body["delete_id"]

        # go ahead
        self.reactor.advance(PaginationHandler.CLEAR_PURGE_AFTER_MS / 1000 / 2)

        # second task
        channel = self.make_request(
            "DELETE",
            self.url.encode("ascii"),
            content={"purge": True},
            access_token=self.admin_user_tok,
        )

        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertIn("delete_id", channel.json_body)
        delete_id2 = channel.json_body["delete_id"]

        # get status
        channel = self.make_request(
            "GET",
            self.url_status_by_room_id,
            access_token=self.admin_user_tok,
        )

        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual(2, len(channel.json_body["results"]))
        self.assertEqual("complete", channel.json_body["results"][0]["status"])
        self.assertEqual("complete", channel.json_body["results"][1]["status"])
        self.assertEqual(delete_id1, channel.json_body["results"][0]["delete_id"])
        self.assertEqual(delete_id2, channel.json_body["results"][1]["delete_id"])

        # get status after more than clearing time for first task
        # second task is not cleared
        self.reactor.advance(PaginationHandler.CLEAR_PURGE_AFTER_MS / 1000 / 2)

        channel = self.make_request(
            "GET",
            self.url_status_by_room_id,
            access_token=self.admin_user_tok,
        )

        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual(1, len(channel.json_body["results"]))
        self.assertEqual("complete", channel.json_body["results"][0]["status"])
        self.assertEqual(delete_id2, channel.json_body["results"][0]["delete_id"])

        # get status after more than clearing time for all tasks
        self.reactor.advance(PaginationHandler.CLEAR_PURGE_AFTER_MS / 1000 / 2)

        channel = self.make_request(
            "GET",
            self.url_status_by_room_id,
            access_token=self.admin_user_tok,
        )

        self.assertEqual(404, channel.code, msg=channel.json_body)
        self.assertEqual(Codes.NOT_FOUND, channel.json_body["errcode"])

    def test_delete_same_room_twice(self) -> None:
        """Test that the call for delete a room at second time gives an exception."""

        body = {"new_room_user_id": self.admin_user}

        # first call to delete room
        # and do not wait for finish the task
        first_channel = self.make_request(
            "DELETE",
            self.url.encode("ascii"),
            content=body,
            access_token=self.admin_user_tok,
            await_result=False,
        )

        # second call to delete room
        second_channel = self.make_request(
            "DELETE",
            self.url.encode("ascii"),
            content=body,
            access_token=self.admin_user_tok,
        )

        self.assertEqual(400, second_channel.code, msg=second_channel.json_body)
        self.assertEqual(Codes.UNKNOWN, second_channel.json_body["errcode"])
        self.assertEqual(
            f"History purge already in progress for {self.room_id}",
            second_channel.json_body["error"],
        )

        # get result of first call
        first_channel.await_result()
        self.assertEqual(200, first_channel.code, msg=first_channel.json_body)
        self.assertIn("delete_id", first_channel.json_body)

        # check status after finish the task
        self._test_result(
            first_channel.json_body["delete_id"],
            self.other_user,
            expect_new_room=True,
        )

    def test_purge_room_and_block(self) -> None:
        """Test to purge a room and block it.
        Members will not be moved to a new room and will not receive a message.
        """
        # Test that room is not purged
        with self.assertRaises(AssertionError):
            self._is_purged(self.room_id)

        # Test that room is not blocked
        self._is_blocked(self.room_id, expect=False)

        # Assert one user in room
        self._is_member(room_id=self.room_id, user_id=self.other_user)

        channel = self.make_request(
            "DELETE",
            self.url.encode("ascii"),
            content={"block": True, "purge": True},
            access_token=self.admin_user_tok,
        )

        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertIn("delete_id", channel.json_body)
        delete_id = channel.json_body["delete_id"]

        self._test_result(delete_id, self.other_user)

        self._is_purged(self.room_id)
        self._is_blocked(self.room_id, expect=True)
        self._has_no_members(self.room_id)

    def test_purge_room_and_not_block(self) -> None:
        """Test to purge a room and do not block it.
        Members will not be moved to a new room and will not receive a message.
        """
        # Test that room is not purged
        with self.assertRaises(AssertionError):
            self._is_purged(self.room_id)

        # Test that room is not blocked
        self._is_blocked(self.room_id, expect=False)

        # Assert one user in room
        self._is_member(room_id=self.room_id, user_id=self.other_user)

        channel = self.make_request(
            "DELETE",
            self.url.encode("ascii"),
            content={"block": False, "purge": True},
            access_token=self.admin_user_tok,
        )

        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertIn("delete_id", channel.json_body)
        delete_id = channel.json_body["delete_id"]

        self._test_result(delete_id, self.other_user)

        self._is_purged(self.room_id)
        self._is_blocked(self.room_id, expect=False)
        self._has_no_members(self.room_id)

    def test_block_room_and_not_purge(self) -> None:
        """Test to block a room without purging it.
        Members will not be moved to a new room and will not receive a message.
        The room will not be purged.
        """
        # Test that room is not purged
        with self.assertRaises(AssertionError):
            self._is_purged(self.room_id)

        # Test that room is not blocked
        self._is_blocked(self.room_id, expect=False)

        # Assert one user in room
        self._is_member(room_id=self.room_id, user_id=self.other_user)

        channel = self.make_request(
            "DELETE",
            self.url.encode("ascii"),
            content={"block": True, "purge": False},
            access_token=self.admin_user_tok,
        )

        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertIn("delete_id", channel.json_body)
        delete_id = channel.json_body["delete_id"]

        self._test_result(delete_id, self.other_user)

        with self.assertRaises(AssertionError):
            self._is_purged(self.room_id)
        self._is_blocked(self.room_id, expect=True)
        self._has_no_members(self.room_id)

    def test_shutdown_room_consent(self) -> None:
        """Test that we can shutdown rooms with local users who have not
        yet accepted the privacy policy. This used to fail when we tried to
        force part the user from the old room.
        Members will be moved to a new room and will receive a message.
        """
        self.event_creation_handler._block_events_without_consent_error = None

        # Assert one user in room
        users_in_room = self.get_success(self.store.get_users_in_room(self.room_id))
        self.assertEqual([self.other_user], users_in_room)

        # Enable require consent to send events
        self.event_creation_handler._block_events_without_consent_error = "Error"

        # Assert that the user is getting consent error
        self.helper.send(
            self.room_id,
            body="foo",
            tok=self.other_user_tok,
            expect_code=403,
        )

        # Test that room is not purged
        with self.assertRaises(AssertionError):
            self._is_purged(self.room_id)

        # Assert one user in room
        self._is_member(room_id=self.room_id, user_id=self.other_user)

        # Test that the admin can still send shutdown
        channel = self.make_request(
            "DELETE",
            self.url,
            content={"new_room_user_id": self.admin_user},
            access_token=self.admin_user_tok,
        )

        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertIn("delete_id", channel.json_body)
        delete_id = channel.json_body["delete_id"]

        self._test_result(delete_id, self.other_user, expect_new_room=True)

        channel = self.make_request(
            "GET",
            self.url_status_by_room_id,
            access_token=self.admin_user_tok,
        )
        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual(1, len(channel.json_body["results"]))

        # Test that member has moved to new room
        self._is_member(
            room_id=channel.json_body["results"][0]["shutdown_room"]["new_room_id"],
            user_id=self.other_user,
        )

        self._is_purged(self.room_id)
        self._has_no_members(self.room_id)

    def test_shutdown_room_block_peek(self) -> None:
        """Test that a world_readable room can no longer be peeked into after
        it has been shut down.
        Members will be moved to a new room and will receive a message.
        """
        self.event_creation_handler._block_events_without_consent_error = None

        # Enable world readable
        url = "rooms/%s/state/m.room.history_visibility" % (self.room_id,)
        channel = self.make_request(
            "PUT",
            url.encode("ascii"),
            content={"history_visibility": "world_readable"},
            access_token=self.other_user_tok,
        )
        self.assertEqual(200, channel.code, msg=channel.json_body)

        # Test that room is not purged
        with self.assertRaises(AssertionError):
            self._is_purged(self.room_id)

        # Assert one user in room
        self._is_member(room_id=self.room_id, user_id=self.other_user)

        # Test that the admin can still send shutdown
        channel = self.make_request(
            "DELETE",
            self.url,
            content={"new_room_user_id": self.admin_user},
            access_token=self.admin_user_tok,
        )

        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertIn("delete_id", channel.json_body)
        delete_id = channel.json_body["delete_id"]

        self._test_result(delete_id, self.other_user, expect_new_room=True)

        channel = self.make_request(
            "GET",
            self.url_status_by_room_id,
            access_token=self.admin_user_tok,
        )
        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual(1, len(channel.json_body["results"]))

        # Test that member has moved to new room
        self._is_member(
            room_id=channel.json_body["results"][0]["shutdown_room"]["new_room_id"],
            user_id=self.other_user,
        )

        self._is_purged(self.room_id)
        self._has_no_members(self.room_id)

        # Assert we can no longer peek into the room
        self._assert_peek(self.room_id, expect_code=403)

    def _is_blocked(self, room_id: str, expect: bool = True) -> None:
        """Assert that the room is blocked or not"""
        d = self.store.is_room_blocked(room_id)
        if expect:
            self.assertTrue(self.get_success(d))
        else:
            self.assertIsNone(self.get_success(d))

    def _has_no_members(self, room_id: str) -> None:
        """Assert there is now no longer anyone in the room"""
        users_in_room = self.get_success(self.store.get_users_in_room(room_id))
        self.assertEqual([], users_in_room)

    def _is_member(self, room_id: str, user_id: str) -> None:
        """Test that user is member of the room"""
        users_in_room = self.get_success(self.store.get_users_in_room(room_id))
        self.assertIn(user_id, users_in_room)

    def _is_purged(self, room_id: str) -> None:
        """Test that the following tables have been purged of all rows related to the room."""
        for table in PURGE_TABLES:
            count = self.get_success(
                self.store.db_pool.simple_select_one_onecol(
                    table=table,
                    keyvalues={"room_id": room_id},
                    retcol="COUNT(*)",
                    desc="test_purge_room",
                )
            )

            self.assertEqual(count, 0, msg=f"Rows not purged in {table}")

    def _assert_peek(self, room_id: str, expect_code: int) -> None:
        """Assert that the admin user can (or cannot) peek into the room."""

        url = f"rooms/{room_id}/initialSync"
        channel = self.make_request(
            "GET", url.encode("ascii"), access_token=self.admin_user_tok
        )
        self.assertEqual(expect_code, channel.code, msg=channel.json_body)

        url = "events?timeout=0&room_id=" + room_id
        channel = self.make_request(
            "GET", url.encode("ascii"), access_token=self.admin_user_tok
        )
        self.assertEqual(expect_code, channel.code, msg=channel.json_body)

    def _test_result(
        self,
        delete_id: str,
        kicked_user: str,
        expect_new_room: bool = False,
    ) -> None:
        """
        Test that the result is the expected.
        Uses both APIs (status by room_id and delete_id)

        Args:
            delete_id: id of this purge
            kicked_user: a user_id which is kicked from the room
            expect_new_room: if we expect that a new room was created
        """

        # get information by room_id
        channel_room_id = self.make_request(
            "GET",
            self.url_status_by_room_id,
            access_token=self.admin_user_tok,
        )
        self.assertEqual(200, channel_room_id.code, msg=channel_room_id.json_body)
        self.assertEqual(1, len(channel_room_id.json_body["results"]))
        self.assertEqual(
            delete_id, channel_room_id.json_body["results"][0]["delete_id"]
        )

        # get information by delete_id
        channel_delete_id = self.make_request(
            "GET",
            self.url_status_by_delete_id + delete_id,
            access_token=self.admin_user_tok,
        )
        self.assertEqual(
            200,
            channel_delete_id.code,
            msg=channel_delete_id.json_body,
        )

        # test values that are the same in both responses
        for content in [
            channel_room_id.json_body["results"][0],
            channel_delete_id.json_body,
        ]:
            self.assertEqual("complete", content["status"])
            self.assertEqual(kicked_user, content["shutdown_room"]["kicked_users"][0])
            self.assertIn("failed_to_kick_users", content["shutdown_room"])
            self.assertIn("local_aliases", content["shutdown_room"])
            self.assertNotIn("error", content)

            if expect_new_room:
                self.assertIsNotNone(content["shutdown_room"]["new_room_id"])
            else:
                self.assertIsNone(content["shutdown_room"]["new_room_id"])


class RoomTestCase(unittest.HomeserverTestCase):
    """Test /room admin API."""

    servlets = [
        synapse.rest.admin.register_servlets,
        login.register_servlets,
        room.register_servlets,
        directory.register_servlets,
    ]

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        # Create user
        self.admin_user = self.register_user("admin", "pass", admin=True)
        self.admin_user_tok = self.login("admin", "pass")

    def test_list_rooms(self) -> None:
        """Test that we can list rooms"""
        # Create 3 test rooms
        total_rooms = 3
        room_ids = []
        for _ in range(total_rooms):
            room_id = self.helper.create_room_as(
                self.admin_user,
                tok=self.admin_user_tok,
                is_public=True,
            )
            room_ids.append(room_id)

        room_ids.sort()

        # Request the list of rooms
        url = "/_synapse/admin/v1/rooms"
        channel = self.make_request(
            "GET",
            url.encode("ascii"),
            access_token=self.admin_user_tok,
        )

        # Check request completed successfully
        self.assertEqual(200, channel.code, msg=channel.json_body)

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
            self.assertIs(r["federatable"], True)
            self.assertIs(r["public"], True)
            self.assertIn("join_rules", r)
            self.assertIn("guest_access", r)
            self.assertIn("history_visibility", r)
            self.assertIn("state_events", r)
            self.assertIn("room_type", r)
            self.assertIsNone(r["room_type"])

        # Check that the correct number of total rooms was returned
        self.assertEqual(channel.json_body["total_rooms"], total_rooms)

        # Check that the offset is correct
        # Should be 0 as we aren't paginating
        self.assertEqual(channel.json_body["offset"], 0)

        # Check that the prev_batch parameter is not present
        self.assertNotIn("prev_batch", channel.json_body)

        # We shouldn't receive a next token here as there's no further rooms to show
        self.assertNotIn("next_batch", channel.json_body)

    def test_list_rooms_pagination(self) -> None:
        """Test that we can get a full list of rooms through pagination"""
        # Create 5 test rooms
        total_rooms = 5
        room_ids = []
        for _ in range(total_rooms):
            room_id = self.helper.create_room_as(
                self.admin_user, tok=self.admin_user_tok
            )
            room_ids.append(room_id)

        # Set the name of the rooms so we get a consistent returned ordering
        for idx, room_id in enumerate(room_ids):
            self.helper.send_state(
                room_id,
                "m.room.name",
                {"name": str(idx)},
                tok=self.admin_user_tok,
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
                "name",
            )
            channel = self.make_request(
                "GET",
                url.encode("ascii"),
                access_token=self.admin_user_tok,
            )
            self.assertEqual(200, channel.code, msg=channel.json_body)

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
        channel = self.make_request(
            "GET",
            url.encode("ascii"),
            access_token=self.admin_user_tok,
        )
        self.assertEqual(200, channel.code, msg=channel.json_body)

    def test_correct_room_attributes(self) -> None:
        """Test the correct attributes for a room are returned"""
        # Create a test room
        room_id = self.helper.create_room_as(
            self.admin_user,
            tok=self.admin_user_tok,
            extra_content={"creation_content": {"type": RoomTypes.SPACE}},
        )

        test_alias = "#test:test"
        test_room_name = "something"

        # Have another user join the room
        user_2 = self.register_user("user4", "pass")
        user_tok_2 = self.login("user4", "pass")
        self.helper.join(room_id, user_2, tok=user_tok_2)

        # Create a new alias to this room
        url = "/_matrix/client/r0/directory/room/%s" % (urllib.parse.quote(test_alias),)
        channel = self.make_request(
            "PUT",
            url.encode("ascii"),
            {"room_id": room_id},
            access_token=self.admin_user_tok,
        )
        self.assertEqual(200, channel.code, msg=channel.json_body)

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
            room_id,
            "m.room.name",
            {"name": test_room_name},
            tok=self.admin_user_tok,
        )

        # Request the list of rooms
        url = "/_synapse/admin/v1/rooms"
        channel = self.make_request(
            "GET",
            url.encode("ascii"),
            access_token=self.admin_user_tok,
        )
        self.assertEqual(200, channel.code, msg=channel.json_body)

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
        self.assertEqual(RoomTypes.SPACE, r["room_type"])

    def test_room_list_sort_order(self) -> None:
        """Test room list sort ordering. alphabetical name versus number of members,
        reversing the order, etc.
        """

        def _order_test(
            order_type: str,
            expected_room_list: List[str],
            reverse: bool = False,
        ) -> None:
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
            channel = self.make_request(
                "GET",
                url.encode("ascii"),
                access_token=self.admin_user_tok,
            )
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

        # Create 3 test rooms
        room_id_1 = self.helper.create_room_as(self.admin_user, tok=self.admin_user_tok)
        room_id_2 = self.helper.create_room_as(self.admin_user, tok=self.admin_user_tok)
        room_id_3 = self.helper.create_room_as(self.admin_user, tok=self.admin_user_tok)

        # Also create a list sorted by IDs for properties that are equal (and thus sorted by room_id)
        sorted_by_room_id_asc = [room_id_1, room_id_2, room_id_3]
        sorted_by_room_id_asc.sort()
        sorted_by_room_id_desc = sorted_by_room_id_asc.copy()
        sorted_by_room_id_desc.reverse()

        # Set room names in alphabetical order. room 1 -> A, 2 -> B, 3 -> C
        self.helper.send_state(
            room_id_1,
            "m.room.name",
            {"name": "A"},
            tok=self.admin_user_tok,
        )
        self.helper.send_state(
            room_id_2,
            "m.room.name",
            {"name": "B"},
            tok=self.admin_user_tok,
        )
        self.helper.send_state(
            room_id_3,
            "m.room.name",
            {"name": "C"},
            tok=self.admin_user_tok,
        )

        # Set room canonical room aliases
        self._set_canonical_alias(room_id_1, "#A_alias:test", self.admin_user_tok)
        self._set_canonical_alias(room_id_2, "#B_alias:test", self.admin_user_tok)
        self._set_canonical_alias(room_id_3, "#C_alias:test", self.admin_user_tok)

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

        # Test different sort orders, with forward and reverse directions
        _order_test("name", [room_id_1, room_id_2, room_id_3])
        _order_test("name", [room_id_3, room_id_2, room_id_1], reverse=True)

        _order_test("canonical_alias", [room_id_1, room_id_2, room_id_3])
        _order_test("canonical_alias", [room_id_3, room_id_2, room_id_1], reverse=True)

        # Note: joined_member counts are sorted in descending order when dir=f
        _order_test("joined_members", [room_id_3, room_id_2, room_id_1])
        _order_test("joined_members", [room_id_1, room_id_2, room_id_3], reverse=True)

        # Note: joined_local_member counts are sorted in descending order when dir=f
        _order_test("joined_local_members", [room_id_3, room_id_2, room_id_1])
        _order_test(
            "joined_local_members", [room_id_1, room_id_2, room_id_3], reverse=True
        )

        # Note: versions are sorted in descending order when dir=f
        _order_test("version", sorted_by_room_id_asc, reverse=True)
        _order_test("version", sorted_by_room_id_desc)

        _order_test("creator", sorted_by_room_id_asc)
        _order_test("creator", sorted_by_room_id_desc, reverse=True)

        _order_test("encryption", sorted_by_room_id_asc)
        _order_test("encryption", sorted_by_room_id_desc, reverse=True)

        _order_test("federatable", sorted_by_room_id_asc)
        _order_test("federatable", sorted_by_room_id_desc, reverse=True)

        _order_test("public", sorted_by_room_id_asc)
        _order_test("public", sorted_by_room_id_desc, reverse=True)

        _order_test("join_rules", sorted_by_room_id_asc)
        _order_test("join_rules", sorted_by_room_id_desc, reverse=True)

        _order_test("guest_access", sorted_by_room_id_asc)
        _order_test("guest_access", sorted_by_room_id_desc, reverse=True)

        _order_test("history_visibility", sorted_by_room_id_asc)
        _order_test("history_visibility", sorted_by_room_id_desc, reverse=True)

        # Note: state_event counts are sorted in descending order when dir=f
        _order_test("state_events", [room_id_3, room_id_2, room_id_1])
        _order_test("state_events", [room_id_1, room_id_2, room_id_3], reverse=True)

    def test_search_term(self) -> None:
        """Test that searching for a room works correctly"""
        # Create two test rooms
        room_id_1 = self.helper.create_room_as(self.admin_user, tok=self.admin_user_tok)
        room_id_2 = self.helper.create_room_as(self.admin_user, tok=self.admin_user_tok)

        room_name_1 = "something"
        room_name_2 = "LoremIpsum"

        # Set the name for each room
        self.helper.send_state(
            room_id_1,
            "m.room.name",
            {"name": room_name_1},
            tok=self.admin_user_tok,
        )
        self.helper.send_state(
            room_id_2,
            "m.room.name",
            {"name": room_name_2},
            tok=self.admin_user_tok,
        )

        self._set_canonical_alias(room_id_1, "#Room_Alias1:test", self.admin_user_tok)

        def _search_test(
            expected_room_id: Optional[str],
            search_term: str,
            expected_http_code: int = 200,
        ) -> None:
            """Search for a room and check that the returned room's id is a match

            Args:
                expected_room_id: The room_id expected to be returned by the API. Set
                    to None to expect zero results for the search
                search_term: The term to search for room names with
                expected_http_code: The expected http code for the request
            """
            url = "/_synapse/admin/v1/rooms?search_term=%s" % (search_term,)
            channel = self.make_request(
                "GET",
                url.encode("ascii"),
                access_token=self.admin_user_tok,
            )
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

        # Test searching by room name
        _search_test(room_id_1, "something")
        _search_test(room_id_1, "thing")

        _search_test(room_id_2, "LoremIpsum")
        _search_test(room_id_2, "lorem")

        # Test case insensitive
        _search_test(room_id_1, "SOMETHING")
        _search_test(room_id_1, "THING")

        _search_test(room_id_2, "LOREMIPSUM")
        _search_test(room_id_2, "LOREM")

        _search_test(None, "foo")
        _search_test(None, "bar")
        _search_test(None, "", expected_http_code=400)

        # Test that the whole room id returns the room
        _search_test(room_id_1, room_id_1)
        # Test that the search by room_id is case sensitive
        _search_test(None, room_id_1.lower())
        # Test search part of local part of room id do not match
        _search_test(None, room_id_1[1:10])

        # Test that whole room alias return no result, because of domain
        _search_test(None, "#Room_Alias1:test")
        # Test search local part of alias
        _search_test(room_id_1, "alias1")

    def test_search_term_non_ascii(self) -> None:
        """Test that searching for a room with non-ASCII characters works correctly"""

        # Create test room
        room_id = self.helper.create_room_as(self.admin_user, tok=self.admin_user_tok)
        room_name = "ж"

        # Set the name for the room
        self.helper.send_state(
            room_id,
            "m.room.name",
            {"name": room_name},
            tok=self.admin_user_tok,
        )

        # make the request and test that the response is what we wanted
        search_term = urllib.parse.quote("ж", "utf-8")
        url = "/_synapse/admin/v1/rooms?search_term=%s" % (search_term,)
        channel = self.make_request(
            "GET",
            url.encode("ascii"),
            access_token=self.admin_user_tok,
        )
        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual(room_id, channel.json_body["rooms"][0].get("room_id"))
        self.assertEqual("ж", channel.json_body["rooms"][0].get("name"))

    def test_single_room(self) -> None:
        """Test that a single room can be requested correctly"""
        # Create two test rooms
        room_id_1 = self.helper.create_room_as(
            self.admin_user, tok=self.admin_user_tok, is_public=True
        )
        room_id_2 = self.helper.create_room_as(
            self.admin_user, tok=self.admin_user_tok, is_public=False
        )

        room_name_1 = "something"
        room_name_2 = "else"

        # Set the name for each room
        self.helper.send_state(
            room_id_1,
            "m.room.name",
            {"name": room_name_1},
            tok=self.admin_user_tok,
        )
        self.helper.send_state(
            room_id_2,
            "m.room.name",
            {"name": room_name_2},
            tok=self.admin_user_tok,
        )

        url = "/_synapse/admin/v1/rooms/%s" % (room_id_1,)
        channel = self.make_request(
            "GET",
            url.encode("ascii"),
            access_token=self.admin_user_tok,
        )
        self.assertEqual(200, channel.code, msg=channel.json_body)

        self.assertIn("room_id", channel.json_body)
        self.assertIn("name", channel.json_body)
        self.assertIn("topic", channel.json_body)
        self.assertIn("avatar", channel.json_body)
        self.assertIn("canonical_alias", channel.json_body)
        self.assertIn("joined_members", channel.json_body)
        self.assertIn("joined_local_members", channel.json_body)
        self.assertIn("joined_local_devices", channel.json_body)
        self.assertIn("version", channel.json_body)
        self.assertIn("creator", channel.json_body)
        self.assertIn("encryption", channel.json_body)
        self.assertIn("federatable", channel.json_body)
        self.assertIn("public", channel.json_body)
        self.assertIn("join_rules", channel.json_body)
        self.assertIn("guest_access", channel.json_body)
        self.assertIn("history_visibility", channel.json_body)
        self.assertIn("state_events", channel.json_body)
        self.assertIn("room_type", channel.json_body)
        self.assertIn("forgotten", channel.json_body)

        self.assertEqual(room_id_1, channel.json_body["room_id"])
        self.assertIs(True, channel.json_body["federatable"])
        self.assertIs(True, channel.json_body["public"])

    def test_single_room_devices(self) -> None:
        """Test that `joined_local_devices` can be requested correctly"""
        room_id_1 = self.helper.create_room_as(self.admin_user, tok=self.admin_user_tok)

        url = "/_synapse/admin/v1/rooms/%s" % (room_id_1,)
        channel = self.make_request(
            "GET",
            url.encode("ascii"),
            access_token=self.admin_user_tok,
        )
        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual(1, channel.json_body["joined_local_devices"])

        # Have another user join the room
        user_1 = self.register_user("foo", "pass")
        user_tok_1 = self.login("foo", "pass")
        self.helper.join(room_id_1, user_1, tok=user_tok_1)

        url = "/_synapse/admin/v1/rooms/%s" % (room_id_1,)
        channel = self.make_request(
            "GET",
            url.encode("ascii"),
            access_token=self.admin_user_tok,
        )
        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual(2, channel.json_body["joined_local_devices"])

        # leave room
        self.helper.leave(room_id_1, self.admin_user, tok=self.admin_user_tok)
        self.helper.leave(room_id_1, user_1, tok=user_tok_1)
        url = "/_synapse/admin/v1/rooms/%s" % (room_id_1,)
        channel = self.make_request(
            "GET",
            url.encode("ascii"),
            access_token=self.admin_user_tok,
        )
        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual(0, channel.json_body["joined_local_devices"])

    def test_room_members(self) -> None:
        """Test that room members can be requested correctly"""
        # Create two test rooms
        room_id_1 = self.helper.create_room_as(self.admin_user, tok=self.admin_user_tok)
        room_id_2 = self.helper.create_room_as(self.admin_user, tok=self.admin_user_tok)

        # Have another user join the room
        user_1 = self.register_user("foo", "pass")
        user_tok_1 = self.login("foo", "pass")
        self.helper.join(room_id_1, user_1, tok=user_tok_1)

        # Have another user join the room
        user_2 = self.register_user("bar", "pass")
        user_tok_2 = self.login("bar", "pass")
        self.helper.join(room_id_1, user_2, tok=user_tok_2)
        self.helper.join(room_id_2, user_2, tok=user_tok_2)

        # Have another user join the room
        user_3 = self.register_user("foobar", "pass")
        user_tok_3 = self.login("foobar", "pass")
        self.helper.join(room_id_2, user_3, tok=user_tok_3)

        url = "/_synapse/admin/v1/rooms/%s/members" % (room_id_1,)
        channel = self.make_request(
            "GET",
            url.encode("ascii"),
            access_token=self.admin_user_tok,
        )
        self.assertEqual(200, channel.code, msg=channel.json_body)

        self.assertCountEqual(
            ["@admin:test", "@foo:test", "@bar:test"], channel.json_body["members"]
        )
        self.assertEqual(channel.json_body["total"], 3)

        url = "/_synapse/admin/v1/rooms/%s/members" % (room_id_2,)
        channel = self.make_request(
            "GET",
            url.encode("ascii"),
            access_token=self.admin_user_tok,
        )
        self.assertEqual(200, channel.code, msg=channel.json_body)

        self.assertCountEqual(
            ["@admin:test", "@bar:test", "@foobar:test"], channel.json_body["members"]
        )
        self.assertEqual(channel.json_body["total"], 3)

    def test_room_state(self) -> None:
        """Test that room state can be requested correctly"""
        # Create two test rooms
        room_id = self.helper.create_room_as(self.admin_user, tok=self.admin_user_tok)

        url = "/_synapse/admin/v1/rooms/%s/state" % (room_id,)
        channel = self.make_request(
            "GET",
            url.encode("ascii"),
            access_token=self.admin_user_tok,
        )
        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertIn("state", channel.json_body)
        # testing that the state events match is painful and not done here. We assume that
        # the create_room already does the right thing, so no need to verify that we got
        # the state events it created.

    def _set_canonical_alias(
        self, room_id: str, test_alias: str, admin_user_tok: str
    ) -> None:
        # Create a new alias to this room
        url = "/_matrix/client/r0/directory/room/%s" % (urllib.parse.quote(test_alias),)
        channel = self.make_request(
            "PUT",
            url.encode("ascii"),
            {"room_id": room_id},
            access_token=admin_user_tok,
        )
        self.assertEqual(200, channel.code, msg=channel.json_body)

        # Set this new alias as the canonical alias for this room
        self.helper.send_state(
            room_id,
            "m.room.aliases",
            {"aliases": [test_alias]},
            tok=admin_user_tok,
            state_key="test",
        )
        self.helper.send_state(
            room_id,
            "m.room.canonical_alias",
            {"alias": test_alias},
            tok=admin_user_tok,
        )

    def test_get_joined_members_after_leave_room(self) -> None:
        """Test that requesting room members after leaving the room raises a 403 error."""

        # create the room
        user = self.register_user("foo", "pass")
        user_tok = self.login("foo", "pass")
        room_id = self.helper.create_room_as(user, tok=user_tok)
        self.helper.leave(room_id, user, tok=user_tok)

        # delete the rooms and get joined roomed membership
        url = f"/_matrix/client/r0/rooms/{room_id}/joined_members"
        channel = self.make_request("GET", url.encode("ascii"), access_token=user_tok)
        self.assertEqual(403, channel.code, msg=channel.json_body)
        self.assertEqual(Codes.FORBIDDEN, channel.json_body["errcode"])


class RoomMessagesTestCase(unittest.HomeserverTestCase):
    servlets = [
        synapse.rest.admin.register_servlets,
        login.register_servlets,
        room.register_servlets,
    ]

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self.admin_user = self.register_user("admin", "pass", admin=True)
        self.admin_user_tok = self.login("admin", "pass")

        self.user = self.register_user("foo", "pass")
        self.user_tok = self.login("foo", "pass")
        self.room_id = self.helper.create_room_as(self.user, tok=self.user_tok)

    def test_timestamp_to_event(self) -> None:
        """Test that providing the current timestamp can get the last event."""
        self.helper.send(self.room_id, body="message 1", tok=self.user_tok)
        second_event_id = self.helper.send(
            self.room_id, body="message 2", tok=self.user_tok
        )["event_id"]
        ts = str(round(time.time() * 1000))

        channel = self.make_request(
            "GET",
            "/_synapse/admin/v1/rooms/%s/timestamp_to_event?dir=b&ts=%s"
            % (self.room_id, ts),
            access_token=self.admin_user_tok,
        )
        self.assertEqual(200, channel.code)
        self.assertIn("event_id", channel.json_body)
        self.assertEqual(second_event_id, channel.json_body["event_id"])

    def test_topo_token_is_accepted(self) -> None:
        """Test Topo Token is accepted."""
        token = "t1-0_0_0_0_0_0_0_0_0"
        channel = self.make_request(
            "GET",
            "/_synapse/admin/v1/rooms/%s/messages?from=%s" % (self.room_id, token),
            access_token=self.admin_user_tok,
        )
        self.assertEqual(200, channel.code)
        self.assertIn("start", channel.json_body)
        self.assertEqual(token, channel.json_body["start"])
        self.assertIn("chunk", channel.json_body)
        self.assertIn("end", channel.json_body)

    def test_stream_token_is_accepted_for_fwd_pagianation(self) -> None:
        """Test that stream token is accepted for forward pagination."""
        token = "s0_0_0_0_0_0_0_0_0"
        channel = self.make_request(
            "GET",
            "/_synapse/admin/v1/rooms/%s/messages?from=%s" % (self.room_id, token),
            access_token=self.admin_user_tok,
        )
        self.assertEqual(200, channel.code)
        self.assertIn("start", channel.json_body)
        self.assertEqual(token, channel.json_body["start"])
        self.assertIn("chunk", channel.json_body)
        self.assertIn("end", channel.json_body)

    def test_room_messages_purge(self) -> None:
        """Test room messages can be retrieved by an admin that isn't in the room."""
        store = self.hs.get_datastores().main
        pagination_handler = self.hs.get_pagination_handler()

        # Send a first message in the room, which will be removed by the purge.
        first_event_id = self.helper.send(
            self.room_id, body="message 1", tok=self.user_tok
        )["event_id"]
        first_token = self.get_success(
            store.get_topological_token_for_event(first_event_id)
        )
        first_token_str = self.get_success(first_token.to_string(store))

        # Send a second message in the room, which won't be removed, and which we'll
        # use as the marker to purge events before.
        second_event_id = self.helper.send(
            self.room_id, body="message 2", tok=self.user_tok
        )["event_id"]
        second_token = self.get_success(
            store.get_topological_token_for_event(second_event_id)
        )
        second_token_str = self.get_success(second_token.to_string(store))

        # Send a third event in the room to ensure we don't fall under any edge case
        # due to our marker being the latest forward extremity in the room.
        self.helper.send(self.room_id, body="message 3", tok=self.user_tok)

        # Check that we get the first and second message when querying /messages.
        channel = self.make_request(
            "GET",
            "/_synapse/admin/v1/rooms/%s/messages?from=%s&dir=b&filter=%s"
            % (
                self.room_id,
                second_token_str,
                json.dumps({"types": [EventTypes.Message]}),
            ),
            access_token=self.admin_user_tok,
        )
        self.assertEqual(channel.code, 200, channel.json_body)

        chunk = channel.json_body["chunk"]
        self.assertEqual(len(chunk), 2, [event["content"] for event in chunk])

        # Purge every event before the second event.
        purge_id = random_string(16)
        pagination_handler._purges_by_id[purge_id] = PurgeStatus()
        self.get_success(
            pagination_handler._purge_history(
                purge_id=purge_id,
                room_id=self.room_id,
                token=second_token_str,
                delete_local_events=True,
            )
        )

        # Check that we only get the second message through /message now that the first
        # has been purged.
        channel = self.make_request(
            "GET",
            "/_synapse/admin/v1/rooms/%s/messages?from=%s&dir=b&filter=%s"
            % (
                self.room_id,
                second_token_str,
                json.dumps({"types": [EventTypes.Message]}),
            ),
            access_token=self.admin_user_tok,
        )
        self.assertEqual(channel.code, 200, channel.json_body)

        chunk = channel.json_body["chunk"]
        self.assertEqual(len(chunk), 1, [event["content"] for event in chunk])

        # Check that we get no event, but also no error, when querying /messages with
        # the token that was pointing at the first event, because we don't have it
        # anymore.
        channel = self.make_request(
            "GET",
            "/_synapse/admin/v1/rooms/%s/messages?from=%s&dir=b&filter=%s"
            % (
                self.room_id,
                first_token_str,
                json.dumps({"types": [EventTypes.Message]}),
            ),
            access_token=self.admin_user_tok,
        )
        self.assertEqual(channel.code, 200, channel.json_body)

        chunk = channel.json_body["chunk"]
        self.assertEqual(len(chunk), 0, [event["content"] for event in chunk])


class JoinAliasRoomTestCase(unittest.HomeserverTestCase):

    servlets = [
        synapse.rest.admin.register_servlets,
        room.register_servlets,
        login.register_servlets,
    ]

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self.admin_user = self.register_user("admin", "pass", admin=True)
        self.admin_user_tok = self.login("admin", "pass")

        self.creator = self.register_user("creator", "test")
        self.creator_tok = self.login("creator", "test")

        self.second_user_id = self.register_user("second", "test")
        self.second_tok = self.login("second", "test")

        self.public_room_id = self.helper.create_room_as(
            self.creator, tok=self.creator_tok, is_public=True
        )
        self.url = f"/_synapse/admin/v1/join/{self.public_room_id}"

    def test_requester_is_no_admin(self) -> None:
        """
        If the user is not a server admin, an error 403 is returned.
        """

        channel = self.make_request(
            "POST",
            self.url,
            content={"user_id": self.second_user_id},
            access_token=self.second_tok,
        )

        self.assertEqual(403, channel.code, msg=channel.json_body)
        self.assertEqual(Codes.FORBIDDEN, channel.json_body["errcode"])

    def test_invalid_parameter(self) -> None:
        """
        If a parameter is missing, return an error
        """

        channel = self.make_request(
            "POST",
            self.url,
            content={"unknown_parameter": "@unknown:test"},
            access_token=self.admin_user_tok,
        )

        self.assertEqual(400, channel.code, msg=channel.json_body)
        self.assertEqual(Codes.MISSING_PARAM, channel.json_body["errcode"])

    def test_local_user_does_not_exist(self) -> None:
        """
        Tests that a lookup for a user that does not exist returns a 404
        """

        channel = self.make_request(
            "POST",
            self.url,
            content={"user_id": "@unknown:test"},
            access_token=self.admin_user_tok,
        )

        self.assertEqual(404, channel.code, msg=channel.json_body)
        self.assertEqual(Codes.NOT_FOUND, channel.json_body["errcode"])

    def test_remote_user(self) -> None:
        """
        Check that only local user can join rooms.
        """

        channel = self.make_request(
            "POST",
            self.url,
            content={"user_id": "@not:exist.bla"},
            access_token=self.admin_user_tok,
        )

        self.assertEqual(400, channel.code, msg=channel.json_body)
        self.assertEqual(
            "This endpoint can only be used with local users",
            channel.json_body["error"],
        )

    def test_room_does_not_exist(self) -> None:
        """
        Check that unknown rooms/server return error 404.
        """
        url = "/_synapse/admin/v1/join/!unknown:test"

        channel = self.make_request(
            "POST",
            url,
            content={"user_id": self.second_user_id},
            access_token=self.admin_user_tok,
        )

        self.assertEqual(404, channel.code, msg=channel.json_body)
        self.assertEqual(
            "Can't join remote room because no servers that are in the room have been provided.",
            channel.json_body["error"],
        )

    def test_room_is_not_valid(self) -> None:
        """
        Check that invalid room names, return an error 400.
        """
        url = "/_synapse/admin/v1/join/invalidroom"

        channel = self.make_request(
            "POST",
            url,
            content={"user_id": self.second_user_id},
            access_token=self.admin_user_tok,
        )

        self.assertEqual(400, channel.code, msg=channel.json_body)
        self.assertEqual(
            "invalidroom was not legal room ID or room alias",
            channel.json_body["error"],
        )

    def test_join_public_room(self) -> None:
        """
        Test joining a local user to a public room with "JoinRules.PUBLIC"
        """

        channel = self.make_request(
            "POST",
            self.url,
            content={"user_id": self.second_user_id},
            access_token=self.admin_user_tok,
        )

        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual(self.public_room_id, channel.json_body["room_id"])

        # Validate if user is a member of the room

        channel = self.make_request(
            "GET",
            "/_matrix/client/r0/joined_rooms",
            access_token=self.second_tok,
        )
        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual(self.public_room_id, channel.json_body["joined_rooms"][0])

    def test_join_private_room_if_not_member(self) -> None:
        """
        Test joining a local user to a private room with "JoinRules.INVITE"
        when server admin is not member of this room.
        """
        private_room_id = self.helper.create_room_as(
            self.creator, tok=self.creator_tok, is_public=False
        )
        url = f"/_synapse/admin/v1/join/{private_room_id}"

        channel = self.make_request(
            "POST",
            url,
            content={"user_id": self.second_user_id},
            access_token=self.admin_user_tok,
        )

        self.assertEqual(403, channel.code, msg=channel.json_body)
        self.assertEqual(Codes.FORBIDDEN, channel.json_body["errcode"])

    def test_join_private_room_if_member(self) -> None:
        """
        Test joining a local user to a private room with "JoinRules.INVITE",
        when server admin is member of this room.
        """
        private_room_id = self.helper.create_room_as(
            self.creator, tok=self.creator_tok, is_public=False
        )
        self.helper.invite(
            room=private_room_id,
            src=self.creator,
            targ=self.admin_user,
            tok=self.creator_tok,
        )
        self.helper.join(
            room=private_room_id, user=self.admin_user, tok=self.admin_user_tok
        )

        # Validate if server admin is a member of the room

        channel = self.make_request(
            "GET",
            "/_matrix/client/r0/joined_rooms",
            access_token=self.admin_user_tok,
        )
        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual(private_room_id, channel.json_body["joined_rooms"][0])

        # Join user to room.

        url = f"/_synapse/admin/v1/join/{private_room_id}"

        channel = self.make_request(
            "POST",
            url,
            content={"user_id": self.second_user_id},
            access_token=self.admin_user_tok,
        )
        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual(private_room_id, channel.json_body["room_id"])

        # Validate if user is a member of the room

        channel = self.make_request(
            "GET",
            "/_matrix/client/r0/joined_rooms",
            access_token=self.second_tok,
        )
        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual(private_room_id, channel.json_body["joined_rooms"][0])

    def test_join_private_room_if_owner(self) -> None:
        """
        Test joining a local user to a private room with "JoinRules.INVITE",
        when server admin is owner of this room.
        """
        private_room_id = self.helper.create_room_as(
            self.admin_user, tok=self.admin_user_tok, is_public=False
        )
        url = f"/_synapse/admin/v1/join/{private_room_id}"

        channel = self.make_request(
            "POST",
            url,
            content={"user_id": self.second_user_id},
            access_token=self.admin_user_tok,
        )

        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual(private_room_id, channel.json_body["room_id"])

        # Validate if user is a member of the room

        channel = self.make_request(
            "GET",
            "/_matrix/client/r0/joined_rooms",
            access_token=self.second_tok,
        )
        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual(private_room_id, channel.json_body["joined_rooms"][0])

    def test_context_as_non_admin(self) -> None:
        """
        Test that, without being admin, one cannot use the context admin API
        """
        # Create a room.
        user_id = self.register_user("test", "test")
        user_tok = self.login("test", "test")

        self.register_user("test_2", "test")
        user_tok_2 = self.login("test_2", "test")

        room_id = self.helper.create_room_as(user_id, tok=user_tok)

        # Populate the room with events.
        events = []
        for i in range(30):
            events.append(
                self.helper.send_event(
                    room_id, "com.example.test", content={"index": i}, tok=user_tok
                )
            )

        # Now attempt to find the context using the admin API without being admin.
        midway = (len(events) - 1) // 2
        for tok in [user_tok, user_tok_2]:
            channel = self.make_request(
                "GET",
                "/_synapse/admin/v1/rooms/%s/context/%s"
                % (room_id, events[midway]["event_id"]),
                access_token=tok,
            )
            self.assertEqual(403, channel.code, msg=channel.json_body)
            self.assertEqual(Codes.FORBIDDEN, channel.json_body["errcode"])

    def test_context_as_admin(self) -> None:
        """
        Test that, as admin, we can find the context of an event without having joined the room.
        """

        # Create a room. We're not part of it.
        user_id = self.register_user("test", "test")
        user_tok = self.login("test", "test")
        room_id = self.helper.create_room_as(user_id, tok=user_tok)

        # Populate the room with events.
        events = []
        for i in range(30):
            events.append(
                self.helper.send_event(
                    room_id, "com.example.test", content={"index": i}, tok=user_tok
                )
            )

        # Now let's fetch the context for this room.
        midway = (len(events) - 1) // 2
        channel = self.make_request(
            "GET",
            "/_synapse/admin/v1/rooms/%s/context/%s"
            % (room_id, events[midway]["event_id"]),
            access_token=self.admin_user_tok,
        )
        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual(
            channel.json_body["event"]["event_id"], events[midway]["event_id"]
        )

        for found_event in channel.json_body["events_before"]:
            for j, posted_event in enumerate(events):
                if found_event["event_id"] == posted_event["event_id"]:
                    self.assertTrue(j < midway)
                    break
            else:
                self.fail("Event %s from events_before not found" % j)

        for found_event in channel.json_body["events_after"]:
            for j, posted_event in enumerate(events):
                if found_event["event_id"] == posted_event["event_id"]:
                    self.assertTrue(j > midway)
                    break
            else:
                self.fail("Event %s from events_after not found" % j)


class MakeRoomAdminTestCase(unittest.HomeserverTestCase):
    servlets = [
        synapse.rest.admin.register_servlets,
        room.register_servlets,
        login.register_servlets,
    ]

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self.admin_user = self.register_user("admin", "pass", admin=True)
        self.admin_user_tok = self.login("admin", "pass")

        self.creator = self.register_user("creator", "test")
        self.creator_tok = self.login("creator", "test")

        self.second_user_id = self.register_user("second", "test")
        self.second_tok = self.login("second", "test")

        self.public_room_id = self.helper.create_room_as(
            self.creator, tok=self.creator_tok, is_public=True
        )
        self.url = "/_synapse/admin/v1/rooms/{}/make_room_admin".format(
            self.public_room_id
        )

    def test_public_room(self) -> None:
        """Test that getting admin in a public room works."""
        room_id = self.helper.create_room_as(
            self.creator, tok=self.creator_tok, is_public=True
        )

        channel = self.make_request(
            "POST",
            f"/_synapse/admin/v1/rooms/{room_id}/make_room_admin",
            content={},
            access_token=self.admin_user_tok,
        )

        self.assertEqual(200, channel.code, msg=channel.json_body)

        # Now we test that we can join the room and ban a user.
        self.helper.join(room_id, self.admin_user, tok=self.admin_user_tok)
        self.helper.change_membership(
            room_id,
            self.admin_user,
            "@test:test",
            Membership.BAN,
            tok=self.admin_user_tok,
        )

    def test_private_room(self) -> None:
        """Test that getting admin in a private room works and we get invited."""
        room_id = self.helper.create_room_as(
            self.creator,
            tok=self.creator_tok,
            is_public=False,
        )

        channel = self.make_request(
            "POST",
            f"/_synapse/admin/v1/rooms/{room_id}/make_room_admin",
            content={},
            access_token=self.admin_user_tok,
        )

        self.assertEqual(200, channel.code, msg=channel.json_body)

        # Now we test that we can join the room (we should have received an
        # invite) and can ban a user.
        self.helper.join(room_id, self.admin_user, tok=self.admin_user_tok)
        self.helper.change_membership(
            room_id,
            self.admin_user,
            "@test:test",
            Membership.BAN,
            tok=self.admin_user_tok,
        )

    def test_other_user(self) -> None:
        """Test that giving admin in a public room works to a non-admin user works."""
        room_id = self.helper.create_room_as(
            self.creator, tok=self.creator_tok, is_public=True
        )

        channel = self.make_request(
            "POST",
            f"/_synapse/admin/v1/rooms/{room_id}/make_room_admin",
            content={"user_id": self.second_user_id},
            access_token=self.admin_user_tok,
        )

        self.assertEqual(200, channel.code, msg=channel.json_body)

        # Now we test that we can join the room and ban a user.
        self.helper.join(room_id, self.second_user_id, tok=self.second_tok)
        self.helper.change_membership(
            room_id,
            self.second_user_id,
            "@test:test",
            Membership.BAN,
            tok=self.second_tok,
        )

    def test_not_enough_power(self) -> None:
        """Test that we get a sensible error if there are no local room admins."""
        room_id = self.helper.create_room_as(
            self.creator, tok=self.creator_tok, is_public=True
        )

        # The creator drops admin rights in the room.
        pl = self.helper.get_state(
            room_id, EventTypes.PowerLevels, tok=self.creator_tok
        )
        pl["users"][self.creator] = 0
        self.helper.send_state(
            room_id, EventTypes.PowerLevels, body=pl, tok=self.creator_tok
        )

        channel = self.make_request(
            "POST",
            f"/_synapse/admin/v1/rooms/{room_id}/make_room_admin",
            content={},
            access_token=self.admin_user_tok,
        )

        # We expect this to fail with a 400 as there are no room admins.
        #
        # (Note we assert the error message to ensure that it's not denied for
        # some other reason)
        self.assertEqual(400, channel.code, msg=channel.json_body)
        self.assertEqual(
            channel.json_body["error"],
            "No local admin user in room with power to update power levels.",
        )


class BlockRoomTestCase(unittest.HomeserverTestCase):
    servlets = [
        synapse.rest.admin.register_servlets,
        room.register_servlets,
        login.register_servlets,
    ]

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self._store = hs.get_datastores().main

        self.admin_user = self.register_user("admin", "pass", admin=True)
        self.admin_user_tok = self.login("admin", "pass")

        self.other_user = self.register_user("user", "pass")
        self.other_user_tok = self.login("user", "pass")

        self.room_id = self.helper.create_room_as(
            self.other_user, tok=self.other_user_tok
        )
        self.url = "/_synapse/admin/v1/rooms/%s/block"

    @parameterized.expand([("PUT",), ("GET",)])
    def test_requester_is_no_admin(self, method: str) -> None:
        """If the user is not a server admin, an error 403 is returned."""

        channel = self.make_request(
            method,
            self.url % self.room_id,
            content={},
            access_token=self.other_user_tok,
        )

        self.assertEqual(403, channel.code, msg=channel.json_body)
        self.assertEqual(Codes.FORBIDDEN, channel.json_body["errcode"])

    @parameterized.expand([("PUT",), ("GET",)])
    def test_room_is_not_valid(self, method: str) -> None:
        """Check that invalid room names, return an error 400."""

        channel = self.make_request(
            method,
            self.url % "invalidroom",
            content={},
            access_token=self.admin_user_tok,
        )

        self.assertEqual(400, channel.code, msg=channel.json_body)
        self.assertEqual(
            "invalidroom is not a legal room ID",
            channel.json_body["error"],
        )

    def test_block_is_not_valid(self) -> None:
        """If parameter `block` is not valid, return an error."""

        # `block` is not valid
        channel = self.make_request(
            "PUT",
            self.url % self.room_id,
            content={"block": "NotBool"},
            access_token=self.admin_user_tok,
        )

        self.assertEqual(400, channel.code, msg=channel.json_body)
        self.assertEqual(Codes.BAD_JSON, channel.json_body["errcode"])

        # `block` is not set
        channel = self.make_request(
            "PUT",
            self.url % self.room_id,
            content={},
            access_token=self.admin_user_tok,
        )

        self.assertEqual(400, channel.code, msg=channel.json_body)
        self.assertEqual(Codes.MISSING_PARAM, channel.json_body["errcode"])

        # no content is send
        channel = self.make_request(
            "PUT",
            self.url % self.room_id,
            access_token=self.admin_user_tok,
        )

        self.assertEqual(400, channel.code, msg=channel.json_body)
        self.assertEqual(Codes.NOT_JSON, channel.json_body["errcode"])

    def test_block_room(self) -> None:
        """Test that block a room is successful."""

        def _request_and_test_block_room(room_id: str) -> None:
            self._is_blocked(room_id, expect=False)
            channel = self.make_request(
                "PUT",
                self.url % room_id,
                content={"block": True},
                access_token=self.admin_user_tok,
            )
            self.assertEqual(200, channel.code, msg=channel.json_body)
            self.assertTrue(channel.json_body["block"])
            self._is_blocked(room_id, expect=True)

        # known internal room
        _request_and_test_block_room(self.room_id)

        # unknown internal room
        _request_and_test_block_room("!unknown:test")

        # unknown remote room
        _request_and_test_block_room("!unknown:remote")

    def test_block_room_twice(self) -> None:
        """Test that block a room that is already blocked is successful."""

        self._is_blocked(self.room_id, expect=False)
        for _ in range(2):
            channel = self.make_request(
                "PUT",
                self.url % self.room_id,
                content={"block": True},
                access_token=self.admin_user_tok,
            )
            self.assertEqual(200, channel.code, msg=channel.json_body)
            self.assertTrue(channel.json_body["block"])
            self._is_blocked(self.room_id, expect=True)

    def test_unblock_room(self) -> None:
        """Test that unblock a room is successful."""

        def _request_and_test_unblock_room(room_id: str) -> None:
            self._block_room(room_id)

            channel = self.make_request(
                "PUT",
                self.url % room_id,
                content={"block": False},
                access_token=self.admin_user_tok,
            )
            self.assertEqual(200, channel.code, msg=channel.json_body)
            self.assertFalse(channel.json_body["block"])
            self._is_blocked(room_id, expect=False)

        # known internal room
        _request_and_test_unblock_room(self.room_id)

        # unknown internal room
        _request_and_test_unblock_room("!unknown:test")

        # unknown remote room
        _request_and_test_unblock_room("!unknown:remote")

    def test_unblock_room_twice(self) -> None:
        """Test that unblock a room that is not blocked is successful."""

        self._block_room(self.room_id)
        for _ in range(2):
            channel = self.make_request(
                "PUT",
                self.url % self.room_id,
                content={"block": False},
                access_token=self.admin_user_tok,
            )
            self.assertEqual(200, channel.code, msg=channel.json_body)
            self.assertFalse(channel.json_body["block"])
            self._is_blocked(self.room_id, expect=False)

    def test_get_blocked_room(self) -> None:
        """Test get status of a blocked room"""

        def _request_blocked_room(room_id: str) -> None:
            self._block_room(room_id)

            channel = self.make_request(
                "GET",
                self.url % room_id,
                access_token=self.admin_user_tok,
            )
            self.assertEqual(200, channel.code, msg=channel.json_body)
            self.assertTrue(channel.json_body["block"])
            self.assertEqual(self.other_user, channel.json_body["user_id"])

        # known internal room
        _request_blocked_room(self.room_id)

        # unknown internal room
        _request_blocked_room("!unknown:test")

        # unknown remote room
        _request_blocked_room("!unknown:remote")

    def test_get_unblocked_room(self) -> None:
        """Test get status of a unblocked room"""

        def _request_unblocked_room(room_id: str) -> None:
            self._is_blocked(room_id, expect=False)

            channel = self.make_request(
                "GET",
                self.url % room_id,
                access_token=self.admin_user_tok,
            )
            self.assertEqual(200, channel.code, msg=channel.json_body)
            self.assertFalse(channel.json_body["block"])
            self.assertNotIn("user_id", channel.json_body)

        # known internal room
        _request_unblocked_room(self.room_id)

        # unknown internal room
        _request_unblocked_room("!unknown:test")

        # unknown remote room
        _request_unblocked_room("!unknown:remote")

    def _is_blocked(self, room_id: str, expect: bool = True) -> None:
        """Assert that the room is blocked or not"""
        d = self._store.is_room_blocked(room_id)
        if expect:
            self.assertTrue(self.get_success(d))
        else:
            self.assertIsNone(self.get_success(d))

    def _block_room(self, room_id: str) -> None:
        """Block a room in database"""
        self.get_success(self._store.block_room(room_id, self.other_user))
        self._is_blocked(room_id, expect=True)


PURGE_TABLES = [
    "current_state_events",
    "event_backward_extremities",
    "event_forward_extremities",
    "event_json",
    "event_push_actions",
    "event_search",
    "events",
    "receipts_graph",
    "receipts_linearized",
    "room_aliases",
    "room_depth",
    "room_memberships",
    "room_stats_state",
    "room_stats_current",
    "room_stats_earliest_token",
    "rooms",
    "stream_ordering_to_exterm",
    "users_in_public_rooms",
    "users_who_share_private_rooms",
    "appservice_room_list",
    "e2e_room_keys",
    "event_push_summary",
    "pusher_throttle",
    "room_account_data",
    "room_tags",
    # "state_groups",  # Current impl leaves orphaned state groups around.
    "state_groups_state",
    "federation_inbound_events_staging",
]
