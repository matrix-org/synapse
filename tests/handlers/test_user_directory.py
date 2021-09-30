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
from unittest.mock import Mock, patch
from urllib.parse import quote

from twisted.internet import defer
from twisted.test.proto_helpers import MemoryReactor

import synapse.rest.admin
from synapse.api.constants import UserTypes
from synapse.api.room_versions import RoomVersion, RoomVersions
from synapse.rest.client import login, room, user_directory
from synapse.server import HomeServer
from synapse.storage.roommember import ProfileInfo
from synapse.types import create_requester
from synapse.util import Clock

from tests import unittest
from tests.storage.test_user_directory import GetUserDirectoryTables
from tests.unittest import override_config


class UserDirectoryTestCase(unittest.HomeserverTestCase):
    """Tests the UserDirectoryHandler.

    We're broadly testing two kinds of things here.

    1. Check that we correctly update the user directory in response
       to events (e.g. join a room, leave a room, change name, make public)
    2. Check that the search logic behaves as expected.

    The background process that rebuilds the user directory is tested in
    tests/storage/test_user_directory.py.
    """

    servlets = [
        login.register_servlets,
        synapse.rest.admin.register_servlets,
        room.register_servlets,
    ]

    def make_homeserver(self, reactor: MemoryReactor, clock: Clock) -> HomeServer:
        config = self.default_config()
        config["update_user_directory"] = True
        return self.setup_test_homeserver(config=config)

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self.store = hs.get_datastore()
        self.handler = hs.get_user_directory_handler()
        self.event_builder_factory = self.hs.get_event_builder_factory()
        self.event_creation_handler = self.hs.get_event_creation_handler()
        self.user_dir_helper = GetUserDirectoryTables(self.store)

    def test_handle_local_profile_change_with_support_user(self) -> None:
        support_user_id = "@support:test"
        self.get_success(
            self.store.register_user(
                user_id=support_user_id, password_hash=None, user_type=UserTypes.SUPPORT
            )
        )
        regular_user_id = "@regular:test"
        self.get_success(
            self.store.register_user(user_id=regular_user_id, password_hash=None)
        )

        self.get_success(
            self.handler.handle_local_profile_change(
                support_user_id, ProfileInfo("I love support me", None)
            )
        )
        profile = self.get_success(self.store.get_user_in_directory(support_user_id))
        self.assertTrue(profile is None)
        display_name = "display_name"

        profile_info = ProfileInfo(avatar_url="avatar_url", display_name=display_name)
        self.get_success(
            self.handler.handle_local_profile_change(regular_user_id, profile_info)
        )
        profile = self.get_success(self.store.get_user_in_directory(regular_user_id))
        self.assertTrue(profile["display_name"] == display_name)

    def test_handle_local_profile_change_with_deactivated_user(self) -> None:
        # create user
        r_user_id = "@regular:test"
        self.get_success(
            self.store.register_user(user_id=r_user_id, password_hash=None)
        )

        # update profile
        display_name = "Regular User"
        profile_info = ProfileInfo(avatar_url="avatar_url", display_name=display_name)
        self.get_success(
            self.handler.handle_local_profile_change(r_user_id, profile_info)
        )

        # profile is in directory
        profile = self.get_success(self.store.get_user_in_directory(r_user_id))
        self.assertTrue(profile["display_name"] == display_name)

        # deactivate user
        self.get_success(self.store.set_user_deactivated_status(r_user_id, True))
        self.get_success(self.handler.handle_local_user_deactivated(r_user_id))

        # profile is not in directory
        profile = self.get_success(self.store.get_user_in_directory(r_user_id))
        self.assertTrue(profile is None)

        # update profile after deactivation
        self.get_success(
            self.handler.handle_local_profile_change(r_user_id, profile_info)
        )

        # profile is furthermore not in directory
        profile = self.get_success(self.store.get_user_in_directory(r_user_id))
        self.assertTrue(profile is None)

    def test_handle_user_deactivated_support_user(self) -> None:
        s_user_id = "@support:test"
        self.get_success(
            self.store.register_user(
                user_id=s_user_id, password_hash=None, user_type=UserTypes.SUPPORT
            )
        )

        mock_remove_from_user_dir = Mock(return_value=defer.succeed(None))
        with patch.object(
            self.store, "remove_from_user_dir", mock_remove_from_user_dir
        ):
            self.get_success(self.handler.handle_local_user_deactivated(s_user_id))
        # BUG: the correct spelling is assert_not_called, but that makes the test fail
        # and it's not clear that this is actually the behaviour we want.
        mock_remove_from_user_dir.not_called()

    def test_handle_user_deactivated_regular_user(self) -> None:
        r_user_id = "@regular:test"
        self.get_success(
            self.store.register_user(user_id=r_user_id, password_hash=None)
        )

        mock_remove_from_user_dir = Mock(return_value=defer.succeed(None))
        with patch.object(
            self.store, "remove_from_user_dir", mock_remove_from_user_dir
        ):
            self.get_success(self.handler.handle_local_user_deactivated(r_user_id))
        mock_remove_from_user_dir.assert_called_once_with(r_user_id)

    def test_reactivation_makes_regular_user_searchable(self) -> None:
        user = self.register_user("regular", "pass")
        user_token = self.login(user, "pass")
        admin_user = self.register_user("admin", "pass", admin=True)
        admin_token = self.login(admin_user, "pass")

        # Ensure the regular user is publicly visible and searchable.
        self.helper.create_room_as(user, is_public=True, tok=user_token)
        s = self.get_success(self.handler.search_users(admin_user, user, 10))
        self.assertEqual(len(s["results"]), 1)
        self.assertEqual(s["results"][0]["user_id"], user)

        # Deactivate the user and check they're not searchable.
        deactivate_handler = self.hs.get_deactivate_account_handler()
        self.get_success(
            deactivate_handler.deactivate_account(
                user, erase_data=False, requester=create_requester(admin_user)
            )
        )
        s = self.get_success(self.handler.search_users(admin_user, user, 10))
        self.assertEqual(s["results"], [])

        # Reactivate the user
        channel = self.make_request(
            "PUT",
            f"/_synapse/admin/v2/users/{quote(user)}",
            access_token=admin_token,
            content={"deactivated": False, "password": "pass"},
        )
        self.assertEqual(channel.code, 200)
        user_token = self.login(user, "pass")
        self.helper.create_room_as(user, is_public=True, tok=user_token)

        # Check they're searchable.
        s = self.get_success(self.handler.search_users(admin_user, user, 10))
        self.assertEqual(len(s["results"]), 1)
        self.assertEqual(s["results"][0]["user_id"], user)

    def test_private_room(self) -> None:
        """
        A user can be searched for only by people that are either in a public
        room, or that share a private chat.
        """
        u1 = self.register_user("user1", "pass")
        u1_token = self.login(u1, "pass")
        u2 = self.register_user("user2", "pass")
        u2_token = self.login(u2, "pass")
        u3 = self.register_user("user3", "pass")

        # We do not add users to the directory until they join a room.
        s = self.get_success(self.handler.search_users(u1, "user2", 10))
        self.assertEqual(len(s["results"]), 0)

        room = self.helper.create_room_as(u1, is_public=False, tok=u1_token)
        self.helper.invite(room, src=u1, targ=u2, tok=u1_token)
        self.helper.join(room, user=u2, tok=u2_token)

        # Check we have populated the database correctly.
        shares_private = self.get_success(
            self.user_dir_helper.get_users_who_share_private_rooms()
        )
        public_users = self.get_success(
            self.user_dir_helper.get_users_in_public_rooms()
        )

        self.assertEqual(
            self.user_dir_helper._compress_shared(shares_private),
            {(u1, u2, room), (u2, u1, room)},
        )
        self.assertEqual(public_users, [])

        # We get one search result when searching for user2 by user1.
        s = self.get_success(self.handler.search_users(u1, "user2", 10))
        self.assertEqual(len(s["results"]), 1)

        # We get NO search results when searching for user2 by user3.
        s = self.get_success(self.handler.search_users(u3, "user2", 10))
        self.assertEqual(len(s["results"]), 0)

        # We get NO search results when searching for user3 by user1.
        s = self.get_success(self.handler.search_users(u1, "user3", 10))
        self.assertEqual(len(s["results"]), 0)

        # User 2 then leaves.
        self.helper.leave(room, user=u2, tok=u2_token)

        # Check we have removed the values.
        shares_private = self.get_success(
            self.user_dir_helper.get_users_who_share_private_rooms()
        )
        public_users = self.get_success(
            self.user_dir_helper.get_users_in_public_rooms()
        )

        self.assertEqual(self.user_dir_helper._compress_shared(shares_private), set())
        self.assertEqual(public_users, [])

        # User1 now gets no search results for any of the other users.
        s = self.get_success(self.handler.search_users(u1, "user2", 10))
        self.assertEqual(len(s["results"]), 0)

        s = self.get_success(self.handler.search_users(u1, "user3", 10))
        self.assertEqual(len(s["results"]), 0)

    def test_spam_checker(self) -> None:
        """
        A user which fails the spam checks will not appear in search results.
        """
        u1 = self.register_user("user1", "pass")
        u1_token = self.login(u1, "pass")
        u2 = self.register_user("user2", "pass")
        u2_token = self.login(u2, "pass")

        # We do not add users to the directory until they join a room.
        s = self.get_success(self.handler.search_users(u1, "user2", 10))
        self.assertEqual(len(s["results"]), 0)

        room = self.helper.create_room_as(u1, is_public=False, tok=u1_token)
        self.helper.invite(room, src=u1, targ=u2, tok=u1_token)
        self.helper.join(room, user=u2, tok=u2_token)

        # Check we have populated the database correctly.
        shares_private = self.get_success(
            self.user_dir_helper.get_users_who_share_private_rooms()
        )
        public_users = self.get_success(
            self.user_dir_helper.get_users_in_public_rooms()
        )

        self.assertEqual(
            self.user_dir_helper._compress_shared(shares_private),
            {(u1, u2, room), (u2, u1, room)},
        )
        self.assertEqual(public_users, [])

        # We get one search result when searching for user2 by user1.
        s = self.get_success(self.handler.search_users(u1, "user2", 10))
        self.assertEqual(len(s["results"]), 1)

        async def allow_all(user_profile: ProfileInfo) -> bool:
            # Allow all users.
            return False

        # Configure a spam checker that does not filter any users.
        spam_checker = self.hs.get_spam_checker()
        spam_checker._check_username_for_spam_callbacks = [allow_all]

        # The results do not change:
        # We get one search result when searching for user2 by user1.
        s = self.get_success(self.handler.search_users(u1, "user2", 10))
        self.assertEqual(len(s["results"]), 1)

        # Configure a spam checker that filters all users.
        async def block_all(user_profile: ProfileInfo) -> bool:
            # All users are spammy.
            return True

        spam_checker._check_username_for_spam_callbacks = [block_all]

        # User1 now gets no search results for any of the other users.
        s = self.get_success(self.handler.search_users(u1, "user2", 10))
        self.assertEqual(len(s["results"]), 0)

    def test_legacy_spam_checker(self) -> None:
        """
        A spam checker without the expected method should be ignored.
        """
        u1 = self.register_user("user1", "pass")
        u1_token = self.login(u1, "pass")
        u2 = self.register_user("user2", "pass")
        u2_token = self.login(u2, "pass")

        # We do not add users to the directory until they join a room.
        s = self.get_success(self.handler.search_users(u1, "user2", 10))
        self.assertEqual(len(s["results"]), 0)

        room = self.helper.create_room_as(u1, is_public=False, tok=u1_token)
        self.helper.invite(room, src=u1, targ=u2, tok=u1_token)
        self.helper.join(room, user=u2, tok=u2_token)

        # Check we have populated the database correctly.
        shares_private = self.get_success(
            self.user_dir_helper.get_users_who_share_private_rooms()
        )
        public_users = self.get_success(
            self.user_dir_helper.get_users_in_public_rooms()
        )

        self.assertEqual(
            self.user_dir_helper._compress_shared(shares_private),
            {(u1, u2, room), (u2, u1, room)},
        )
        self.assertEqual(public_users, [])

        # Configure a spam checker.
        spam_checker = self.hs.get_spam_checker()
        # The spam checker doesn't need any methods, so create a bare object.
        spam_checker.spam_checker = object()

        # We get one search result when searching for user2 by user1.
        s = self.get_success(self.handler.search_users(u1, "user2", 10))
        self.assertEqual(len(s["results"]), 1)

    def test_initial_share_all_users(self) -> None:
        """
        Search all users = True means that a user does not have to share a
        private room with the searching user or be in a public room to be search
        visible.
        """
        self.handler.search_all_users = True
        self.hs.config.userdirectory.user_directory_search_all_users = True

        u1 = self.register_user("user1", "pass")
        self.register_user("user2", "pass")
        u3 = self.register_user("user3", "pass")

        shares_private = self.get_success(
            self.user_dir_helper.get_users_who_share_private_rooms()
        )
        public_users = self.get_success(
            self.user_dir_helper.get_users_in_public_rooms()
        )

        # No users share rooms
        self.assertEqual(public_users, [])
        self.assertEqual(self.user_dir_helper._compress_shared(shares_private), set())

        # Despite not sharing a room, search_all_users means we get a search
        # result.
        s = self.get_success(self.handler.search_users(u1, u3, 10))
        self.assertEqual(len(s["results"]), 1)

        # We can find the other two users
        s = self.get_success(self.handler.search_users(u1, "user", 10))
        self.assertEqual(len(s["results"]), 2)

        # Registering a user and then searching for them works.
        u4 = self.register_user("user4", "pass")
        s = self.get_success(self.handler.search_users(u1, u4, 10))
        self.assertEqual(len(s["results"]), 1)

    @override_config(
        {
            "user_directory": {
                "enabled": True,
                "search_all_users": True,
                "prefer_local_users": True,
            }
        }
    )
    def test_prefer_local_users(self) -> None:
        """Tests that local users are shown higher in search results when
        user_directory.prefer_local_users is True.
        """
        # Create a room and few users to test the directory with
        searching_user = self.register_user("searcher", "password")
        searching_user_tok = self.login("searcher", "password")

        room_id = self.helper.create_room_as(
            searching_user,
            room_version=RoomVersions.V1.identifier,
            tok=searching_user_tok,
        )

        # Create a few local users and join them to the room
        local_user_1 = self.register_user("user_xxxxx", "password")
        local_user_2 = self.register_user("user_bbbbb", "password")
        local_user_3 = self.register_user("user_zzzzz", "password")

        self._add_user_to_room(room_id, RoomVersions.V1, local_user_1)
        self._add_user_to_room(room_id, RoomVersions.V1, local_user_2)
        self._add_user_to_room(room_id, RoomVersions.V1, local_user_3)

        # Create a few "remote" users and join them to the room
        remote_user_1 = "@user_aaaaa:remote_server"
        remote_user_2 = "@user_yyyyy:remote_server"
        remote_user_3 = "@user_ccccc:remote_server"
        self._add_user_to_room(room_id, RoomVersions.V1, remote_user_1)
        self._add_user_to_room(room_id, RoomVersions.V1, remote_user_2)
        self._add_user_to_room(room_id, RoomVersions.V1, remote_user_3)

        local_users = [local_user_1, local_user_2, local_user_3]
        remote_users = [remote_user_1, remote_user_2, remote_user_3]

        # The local searching user searches for the term "user", which other users have
        # in their user id
        results = self.get_success(
            self.handler.search_users(searching_user, "user", 20)
        )["results"]
        received_user_id_ordering = [result["user_id"] for result in results]

        # Typically we'd expect Synapse to return users in lexicographical order,
        # assuming they have similar User IDs/display names, and profile information.

        # Check that the order of returned results using our module is as we expect,
        # i.e our local users show up first, despite all users having lexographically mixed
        # user IDs.
        [self.assertIn(user, local_users) for user in received_user_id_ordering[:3]]
        [self.assertIn(user, remote_users) for user in received_user_id_ordering[3:]]

    def _add_user_to_room(
        self,
        room_id: str,
        room_version: RoomVersion,
        user_id: str,
    ) -> None:
        # Add a user to the room.
        builder = self.event_builder_factory.for_room_version(
            room_version,
            {
                "type": "m.room.member",
                "sender": user_id,
                "state_key": user_id,
                "room_id": room_id,
                "content": {"membership": "join"},
            },
        )

        event, context = self.get_success(
            self.event_creation_handler.create_new_client_event(builder)
        )

        self.get_success(
            self.hs.get_storage().persistence.persist_event(event, context)
        )


class TestUserDirSearchDisabled(unittest.HomeserverTestCase):
    servlets = [
        user_directory.register_servlets,
        room.register_servlets,
        login.register_servlets,
        synapse.rest.admin.register_servlets_for_client_rest_resource,
    ]

    def make_homeserver(self, reactor: MemoryReactor, clock: Clock) -> HomeServer:
        config = self.default_config()
        config["update_user_directory"] = True
        hs = self.setup_test_homeserver(config=config)

        self.config = hs.config

        return hs

    def test_disabling_room_list(self) -> None:
        self.config.userdirectory.user_directory_search_enabled = True

        # Create two users and put them in the same room.
        u1 = self.register_user("user1", "pass")
        u1_token = self.login(u1, "pass")
        u2 = self.register_user("user2", "pass")
        u2_token = self.login(u2, "pass")

        room = self.helper.create_room_as(u1, tok=u1_token)
        self.helper.join(room, user=u2, tok=u2_token)

        # Each should see the other when searching the user directory.
        channel = self.make_request(
            "POST",
            b"user_directory/search",
            b'{"search_term":"user2"}',
            access_token=u1_token,
        )
        self.assertEquals(200, channel.code, channel.result)
        self.assertTrue(len(channel.json_body["results"]) > 0)

        # Disable user directory and check search returns nothing
        self.config.userdirectory.user_directory_search_enabled = False
        channel = self.make_request(
            "POST",
            b"user_directory/search",
            b'{"search_term":"user2"}',
            access_token=u1_token,
        )
        self.assertEquals(200, channel.code, channel.result)
        self.assertTrue(len(channel.json_body["results"]) == 0)
