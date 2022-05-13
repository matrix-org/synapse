# Copyright 2021 Dirk Klimpel
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
from http import HTTPStatus
from typing import List

from twisted.test.proto_helpers import MemoryReactor

import synapse.rest.admin
from synapse.api.errors import Codes
from synapse.rest.client import login, room, sync
from synapse.server import HomeServer
from synapse.storage.roommember import RoomsForUser
from synapse.types import JsonDict
from synapse.util import Clock

from tests import unittest
from tests.unittest import override_config


class ServerNoticeTestCase(unittest.HomeserverTestCase):

    servlets = [
        synapse.rest.admin.register_servlets,
        login.register_servlets,
        room.register_servlets,
        sync.register_servlets,
    ]

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self.store = hs.get_datastores().main
        self.room_shutdown_handler = hs.get_room_shutdown_handler()
        self.pagination_handler = hs.get_pagination_handler()
        self.server_notices_manager = self.hs.get_server_notices_manager()

        # Create user
        self.admin_user = self.register_user("admin", "pass", admin=True)
        self.admin_user_tok = self.login("admin", "pass")

        self.other_user = self.register_user("user", "pass")
        self.other_user_token = self.login("user", "pass")

        self.url = "/_synapse/admin/v1/send_server_notice"

    def test_no_auth(self) -> None:
        """Try to send a server notice without authentication."""
        channel = self.make_request("POST", self.url)

        self.assertEqual(
            HTTPStatus.UNAUTHORIZED,
            channel.code,
            msg=channel.json_body,
        )
        self.assertEqual(Codes.MISSING_TOKEN, channel.json_body["errcode"])

    def test_requester_is_no_admin(self) -> None:
        """If the user is not a server admin, an error is returned."""
        channel = self.make_request(
            "POST",
            self.url,
            access_token=self.other_user_token,
        )

        self.assertEqual(
            HTTPStatus.FORBIDDEN,
            channel.code,
            msg=channel.json_body,
        )
        self.assertEqual(Codes.FORBIDDEN, channel.json_body["errcode"])

    @override_config({"server_notices": {"system_mxid_localpart": "notices"}})
    def test_user_does_not_exist(self) -> None:
        """Tests that a lookup for a user that does not exist returns a HTTPStatus.NOT_FOUND"""
        channel = self.make_request(
            "POST",
            self.url,
            access_token=self.admin_user_tok,
            content={"user_id": "@unknown_person:test", "content": ""},
        )

        self.assertEqual(HTTPStatus.NOT_FOUND, channel.code, msg=channel.json_body)
        self.assertEqual(Codes.NOT_FOUND, channel.json_body["errcode"])

    @override_config({"server_notices": {"system_mxid_localpart": "notices"}})
    def test_user_is_not_local(self) -> None:
        """
        Tests that a lookup for a user that is not a local returns a HTTPStatus.BAD_REQUEST
        """
        channel = self.make_request(
            "POST",
            self.url,
            access_token=self.admin_user_tok,
            content={
                "user_id": "@unknown_person:unknown_domain",
                "content": "",
            },
        )

        self.assertEqual(HTTPStatus.BAD_REQUEST, channel.code, msg=channel.json_body)
        self.assertEqual(
            "Server notices can only be sent to local users", channel.json_body["error"]
        )

    @override_config({"server_notices": {"system_mxid_localpart": "notices"}})
    def test_invalid_parameter(self) -> None:
        """If parameters are invalid, an error is returned."""

        # no content, no user
        channel = self.make_request(
            "POST",
            self.url,
            access_token=self.admin_user_tok,
        )

        self.assertEqual(HTTPStatus.BAD_REQUEST, channel.code, msg=channel.json_body)
        self.assertEqual(Codes.NOT_JSON, channel.json_body["errcode"])

        # no content
        channel = self.make_request(
            "POST",
            self.url,
            access_token=self.admin_user_tok,
            content={"user_id": self.other_user},
        )

        self.assertEqual(HTTPStatus.BAD_REQUEST, channel.code, msg=channel.json_body)
        self.assertEqual(Codes.MISSING_PARAM, channel.json_body["errcode"])

        # no body
        channel = self.make_request(
            "POST",
            self.url,
            access_token=self.admin_user_tok,
            content={"user_id": self.other_user, "content": ""},
        )

        self.assertEqual(HTTPStatus.BAD_REQUEST, channel.code, msg=channel.json_body)
        self.assertEqual(Codes.UNKNOWN, channel.json_body["errcode"])
        self.assertEqual("'body' not in content", channel.json_body["error"])

        # no msgtype
        channel = self.make_request(
            "POST",
            self.url,
            access_token=self.admin_user_tok,
            content={"user_id": self.other_user, "content": {"body": ""}},
        )

        self.assertEqual(HTTPStatus.BAD_REQUEST, channel.code, msg=channel.json_body)
        self.assertEqual(Codes.UNKNOWN, channel.json_body["errcode"])
        self.assertEqual("'msgtype' not in content", channel.json_body["error"])

    def test_server_notice_disabled(self) -> None:
        """Tests that server returns error if server notice is disabled"""
        channel = self.make_request(
            "POST",
            self.url,
            access_token=self.admin_user_tok,
            content={
                "user_id": self.other_user,
                "content": "",
            },
        )

        self.assertEqual(HTTPStatus.BAD_REQUEST, channel.code, msg=channel.json_body)
        self.assertEqual(Codes.UNKNOWN, channel.json_body["errcode"])
        self.assertEqual(
            "Server notices are not enabled on this server", channel.json_body["error"]
        )

    @override_config({"server_notices": {"system_mxid_localpart": "notices"}})
    def test_send_server_notice(self) -> None:
        """
        Tests that sending two server notices is successfully,
        the server uses the same room and do not send messages twice.
        """
        # user has no room memberships
        self._check_invite_and_join_status(self.other_user, 0, 0)

        # send first message
        channel = self.make_request(
            "POST",
            self.url,
            access_token=self.admin_user_tok,
            content={
                "user_id": self.other_user,
                "content": {"msgtype": "m.text", "body": "test msg one"},
            },
        )
        self.assertEqual(HTTPStatus.OK, channel.code, msg=channel.json_body)

        # user has one invite
        invited_rooms = self._check_invite_and_join_status(self.other_user, 1, 0)
        room_id = invited_rooms[0].room_id

        # user joins the room and is member now
        self.helper.join(room=room_id, user=self.other_user, tok=self.other_user_token)
        self._check_invite_and_join_status(self.other_user, 0, 1)

        # get messages
        messages = self._sync_and_get_messages(room_id, self.other_user_token)
        self.assertEqual(len(messages), 1)
        self.assertEqual(messages[0]["content"]["body"], "test msg one")
        self.assertEqual(messages[0]["sender"], "@notices:test")

        # invalidate cache of server notices room_ids
        self.server_notices_manager.get_or_create_notice_room_for_user.invalidate_all()

        # send second message
        channel = self.make_request(
            "POST",
            self.url,
            access_token=self.admin_user_tok,
            content={
                "user_id": self.other_user,
                "content": {"msgtype": "m.text", "body": "test msg two"},
            },
        )
        self.assertEqual(HTTPStatus.OK, channel.code, msg=channel.json_body)

        # user has no new invites or memberships
        self._check_invite_and_join_status(self.other_user, 0, 1)

        # get messages
        messages = self._sync_and_get_messages(room_id, self.other_user_token)

        self.assertEqual(len(messages), 2)
        self.assertEqual(messages[0]["content"]["body"], "test msg one")
        self.assertEqual(messages[0]["sender"], "@notices:test")
        self.assertEqual(messages[1]["content"]["body"], "test msg two")
        self.assertEqual(messages[1]["sender"], "@notices:test")

    @override_config({"server_notices": {"system_mxid_localpart": "notices"}})
    def test_send_server_notice_leave_room(self) -> None:
        """
        Tests that sending a server notices is successfully.
        The user leaves the room and the second message appears
        in a new room.
        """
        # user has no room memberships
        self._check_invite_and_join_status(self.other_user, 0, 0)

        # send first message
        channel = self.make_request(
            "POST",
            self.url,
            access_token=self.admin_user_tok,
            content={
                "user_id": self.other_user,
                "content": {"msgtype": "m.text", "body": "test msg one"},
            },
        )
        self.assertEqual(HTTPStatus.OK, channel.code, msg=channel.json_body)

        # user has one invite
        invited_rooms = self._check_invite_and_join_status(self.other_user, 1, 0)
        first_room_id = invited_rooms[0].room_id

        # user joins the room and is member now
        self.helper.join(
            room=first_room_id, user=self.other_user, tok=self.other_user_token
        )
        self._check_invite_and_join_status(self.other_user, 0, 1)

        # get messages
        messages = self._sync_and_get_messages(first_room_id, self.other_user_token)
        self.assertEqual(len(messages), 1)
        self.assertEqual(messages[0]["content"]["body"], "test msg one")
        self.assertEqual(messages[0]["sender"], "@notices:test")

        # user leaves the romm
        self.helper.leave(
            room=first_room_id, user=self.other_user, tok=self.other_user_token
        )

        # user is not member anymore
        self._check_invite_and_join_status(self.other_user, 0, 0)

        # invalidate cache of server notices room_ids
        # if server tries to send to a cached room_id the user gets the message
        # in old room
        self.server_notices_manager.get_or_create_notice_room_for_user.invalidate_all()

        # send second message
        channel = self.make_request(
            "POST",
            self.url,
            access_token=self.admin_user_tok,
            content={
                "user_id": self.other_user,
                "content": {"msgtype": "m.text", "body": "test msg two"},
            },
        )
        self.assertEqual(HTTPStatus.OK, channel.code, msg=channel.json_body)

        # user has one invite
        invited_rooms = self._check_invite_and_join_status(self.other_user, 1, 0)
        second_room_id = invited_rooms[0].room_id

        # user joins the room and is member now
        self.helper.join(
            room=second_room_id, user=self.other_user, tok=self.other_user_token
        )
        self._check_invite_and_join_status(self.other_user, 0, 1)

        # get messages
        messages = self._sync_and_get_messages(second_room_id, self.other_user_token)

        self.assertEqual(len(messages), 1)
        self.assertEqual(messages[0]["content"]["body"], "test msg two")
        self.assertEqual(messages[0]["sender"], "@notices:test")
        # room has the same id
        self.assertNotEqual(first_room_id, second_room_id)

    @override_config({"server_notices": {"system_mxid_localpart": "notices"}})
    def test_send_server_notice_delete_room(self) -> None:
        """
        Tests that the user get server notice in a new room
        after the first server notice room was deleted.
        """
        # user has no room memberships
        self._check_invite_and_join_status(self.other_user, 0, 0)

        # send first message
        channel = self.make_request(
            "POST",
            self.url,
            access_token=self.admin_user_tok,
            content={
                "user_id": self.other_user,
                "content": {"msgtype": "m.text", "body": "test msg one"},
            },
        )
        self.assertEqual(HTTPStatus.OK, channel.code, msg=channel.json_body)

        # user has one invite
        invited_rooms = self._check_invite_and_join_status(self.other_user, 1, 0)
        first_room_id = invited_rooms[0].room_id

        # user joins the room and is member now
        self.helper.join(
            room=first_room_id, user=self.other_user, tok=self.other_user_token
        )
        self._check_invite_and_join_status(self.other_user, 0, 1)

        # get messages
        messages = self._sync_and_get_messages(first_room_id, self.other_user_token)
        self.assertEqual(len(messages), 1)
        self.assertEqual(messages[0]["content"]["body"], "test msg one")
        self.assertEqual(messages[0]["sender"], "@notices:test")

        # shut down and purge room
        self.get_success(
            self.room_shutdown_handler.shutdown_room(first_room_id, self.admin_user)
        )
        self.get_success(self.pagination_handler.purge_room(first_room_id))

        # user is not member anymore
        self._check_invite_and_join_status(self.other_user, 0, 0)

        # It doesn't really matter what API we use here, we just want to assert
        # that the room doesn't exist.
        summary = self.get_success(self.store.get_room_summary(first_room_id))
        # The summary should be empty since the room doesn't exist.
        self.assertEqual(summary, {})

        # invalidate cache of server notices room_ids
        # if server tries to send to a cached room_id it gives an error
        self.server_notices_manager.get_or_create_notice_room_for_user.invalidate_all()

        # send second message
        channel = self.make_request(
            "POST",
            self.url,
            access_token=self.admin_user_tok,
            content={
                "user_id": self.other_user,
                "content": {"msgtype": "m.text", "body": "test msg two"},
            },
        )
        self.assertEqual(HTTPStatus.OK, channel.code, msg=channel.json_body)

        # user has one invite
        invited_rooms = self._check_invite_and_join_status(self.other_user, 1, 0)
        second_room_id = invited_rooms[0].room_id

        # user joins the room and is member now
        self.helper.join(
            room=second_room_id, user=self.other_user, tok=self.other_user_token
        )
        self._check_invite_and_join_status(self.other_user, 0, 1)

        # get message
        messages = self._sync_and_get_messages(second_room_id, self.other_user_token)

        self.assertEqual(len(messages), 1)
        self.assertEqual(messages[0]["content"]["body"], "test msg two")
        self.assertEqual(messages[0]["sender"], "@notices:test")
        # second room has new ID
        self.assertNotEqual(first_room_id, second_room_id)

    @override_config({"server_notices": {"system_mxid_localpart": "notices"}})
    def test_update_notice_user_name_when_changed(self) -> None:
        """
        Tests that existing server notices user name in room is updated after
        server notice config changes.
        """
        server_notice_request_content = {
            "user_id": self.other_user,
            "content": {"msgtype": "m.text", "body": "test msg one"},
        }

        self.make_request(
            "POST",
            self.url,
            access_token=self.admin_user_tok,
            content=server_notice_request_content,
        )

        # simulate a change in server config after a server restart.
        new_display_name = "new display name"
        self.server_notices_manager._config.servernotices.server_notices_mxid_display_name = (
            new_display_name
        )
        self.server_notices_manager.get_or_create_notice_room_for_user.cache.invalidate_all()

        self.make_request(
            "POST",
            self.url,
            access_token=self.admin_user_tok,
            content=server_notice_request_content,
        )

        invited_rooms = self._check_invite_and_join_status(self.other_user, 1, 0)
        notice_room_id = invited_rooms[0].room_id
        self.helper.join(
            room=notice_room_id, user=self.other_user, tok=self.other_user_token
        )

        notice_user_state_in_room = self.helper.get_state(
            notice_room_id,
            "m.room.member",
            self.other_user_token,
            state_key="@notices:test",
        )
        self.assertEqual(notice_user_state_in_room["displayname"], new_display_name)

    @override_config({"server_notices": {"system_mxid_localpart": "notices"}})
    def test_update_notice_user_avatar_when_changed(self) -> None:
        """
        Tests that existing server notices user avatar in room is updated when is
        different from the one in homeserver config.
        """
        server_notice_request_content = {
            "user_id": self.other_user,
            "content": {"msgtype": "m.text", "body": "test msg one"},
        }

        self.make_request(
            "POST",
            self.url,
            access_token=self.admin_user_tok,
            content=server_notice_request_content,
        )

        # simulate a change in server config after a server restart.
        new_avatar_url = "test/new-url"
        self.server_notices_manager._config.servernotices.server_notices_mxid_avatar_url = (
            new_avatar_url
        )
        self.server_notices_manager.get_or_create_notice_room_for_user.cache.invalidate_all()

        self.make_request(
            "POST",
            self.url,
            access_token=self.admin_user_tok,
            content=server_notice_request_content,
        )

        invited_rooms = self._check_invite_and_join_status(self.other_user, 1, 0)
        notice_room_id = invited_rooms[0].room_id
        self.helper.join(
            room=notice_room_id, user=self.other_user, tok=self.other_user_token
        )

        notice_user_state = self.helper.get_state(
            notice_room_id,
            "m.room.member",
            self.other_user_token,
            state_key="@notices:test",
        )
        self.assertEqual(notice_user_state["avatar_url"], new_avatar_url)

    def _check_invite_and_join_status(
        self, user_id: str, expected_invites: int, expected_memberships: int
    ) -> List[RoomsForUser]:
        """Check invite and room membership status of a user.

        Args
            user_id: user to check
            expected_invites: number of expected invites of this user
            expected_memberships: number of expected room memberships of this user
        Returns
            room_ids from the rooms that the user is invited
        """

        invited_rooms = self.get_success(
            self.store.get_invited_rooms_for_local_user(user_id)
        )
        self.assertEqual(expected_invites, len(invited_rooms))

        room_ids = self.get_success(self.store.get_rooms_for_user(user_id))
        self.assertEqual(expected_memberships, len(room_ids))

        return invited_rooms

    def _sync_and_get_messages(self, room_id: str, token: str) -> List[JsonDict]:
        """
        Do a sync and get messages of a room.

        Args
            room_id: room that contains the messages
            token: access token of user

        Returns
            list of messages contained in the room
        """
        channel = self.make_request(
            "GET", "/_matrix/client/r0/sync", access_token=token
        )
        self.assertEqual(channel.code, HTTPStatus.OK)

        # Get the messages
        room = channel.json_body["rooms"]["join"][room_id]
        messages = [
            x for x in room["timeline"]["events"] if x["type"] == "m.room.message"
        ]
        return messages
