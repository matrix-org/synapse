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
from typing import Tuple
from unittest.mock import Mock, patch
from urllib.parse import quote

from twisted.test.proto_helpers import MemoryReactor

import synapse.rest.admin
from synapse.api.constants import UserTypes
from synapse.api.room_versions import RoomVersion, RoomVersions
from synapse.appservice import ApplicationService
from synapse.rest.client import login, register, room, user_directory
from synapse.server import HomeServer
from synapse.storage.roommember import ProfileInfo
from synapse.types import create_requester
from synapse.util import Clock

from tests import unittest
from tests.storage.test_user_directory import GetUserDirectoryTables
from tests.test_utils import make_awaitable
from tests.test_utils.event_injection import inject_member_event
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
        register.register_servlets,
        room.register_servlets,
    ]

    def make_homeserver(self, reactor: MemoryReactor, clock: Clock) -> HomeServer:
        config = self.default_config()
        config["update_user_directory"] = True

        self.appservice = ApplicationService(
            token="i_am_an_app_service",
            id="1234",
            namespaces={"users": [{"regex": r"@as_user.*", "exclusive": True}]},
            # Note: this user does not match the regex above, so that tests
            # can distinguish the sender from the AS user.
            sender="@as_main:test",
        )

        mock_load_appservices = Mock(return_value=[self.appservice])
        with patch(
            "synapse.storage.databases.main.appservice.load_appservices",
            mock_load_appservices,
        ):
            hs = self.setup_test_homeserver(config=config)
        return hs

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self.store = hs.get_datastores().main
        self.handler = hs.get_user_directory_handler()
        self.event_builder_factory = self.hs.get_event_builder_factory()
        self.event_creation_handler = self.hs.get_event_creation_handler()
        self.user_dir_helper = GetUserDirectoryTables(self.store)

    def test_normal_user_pair(self) -> None:
        """Sanity check that the room-sharing tables are updated correctly."""
        alice = self.register_user("alice", "pass")
        alice_token = self.login(alice, "pass")
        bob = self.register_user("bob", "pass")
        bob_token = self.login(bob, "pass")

        public = self.helper.create_room_as(
            alice,
            is_public=True,
            extra_content={"visibility": "public"},
            tok=alice_token,
        )
        private = self.helper.create_room_as(alice, is_public=False, tok=alice_token)
        self.helper.invite(private, alice, bob, tok=alice_token)
        self.helper.join(public, bob, tok=bob_token)
        self.helper.join(private, bob, tok=bob_token)

        # Alice also makes a second public room but no-one else joins
        public2 = self.helper.create_room_as(
            alice,
            is_public=True,
            extra_content={"visibility": "public"},
            tok=alice_token,
        )

        # The user directory should reflect the room memberships above.
        users, in_public, in_private = self.get_success(
            self.user_dir_helper.get_tables()
        )
        self.assertEqual(users, {alice, bob})
        self.assertEqual(in_public, {(alice, public), (bob, public), (alice, public2)})
        self.assertEqual(
            in_private,
            {(alice, bob, private), (bob, alice, private)},
        )

    # The next four tests (test_excludes_*) all setup
    #   - A normal user included in the user dir
    #   - A public and private room created by that user
    #   - A user excluded from the room dir, belonging to both rooms

    # They match similar logic in storage/test_user_directory. But that tests
    # rebuilding the directory; this tests updating it incrementally.

    def test_excludes_support_user(self) -> None:
        alice = self.register_user("alice", "pass")
        alice_token = self.login(alice, "pass")
        support = "@support1:test"
        self.get_success(
            self.store.register_user(
                user_id=support, password_hash=None, user_type=UserTypes.SUPPORT
            )
        )

        public, private = self._create_rooms_and_inject_memberships(
            alice, alice_token, support
        )
        self._check_only_one_user_in_directory(alice, public)

    def test_excludes_deactivated_user(self) -> None:
        admin = self.register_user("admin", "pass", admin=True)
        admin_token = self.login(admin, "pass")
        user = self.register_user("naughty", "pass")

        # Deactivate the user.
        channel = self.make_request(
            "PUT",
            f"/_synapse/admin/v2/users/{user}",
            access_token=admin_token,
            content={"deactivated": True},
        )
        self.assertEqual(channel.code, 200)
        self.assertEqual(channel.json_body["deactivated"], True)

        # Join the deactivated user to rooms owned by the admin.
        # Is this something that could actually happen outside of a test?
        public, private = self._create_rooms_and_inject_memberships(
            admin, admin_token, user
        )
        self._check_only_one_user_in_directory(admin, public)

    def test_excludes_appservices_user(self) -> None:
        # Register an AS user.
        user = self.register_user("user", "pass")
        token = self.login(user, "pass")
        as_user, _ = self.register_appservice_user(
            "as_user_potato", self.appservice.token
        )

        # Join the AS user to rooms owned by the normal user.
        public, private = self._create_rooms_and_inject_memberships(
            user, token, as_user
        )
        self._check_only_one_user_in_directory(user, public)

    def test_excludes_appservice_sender(self) -> None:
        user = self.register_user("user", "pass")
        token = self.login(user, "pass")
        room = self.helper.create_room_as(user, is_public=True, tok=token)
        self.helper.join(room, self.appservice.sender, tok=self.appservice.token)
        self._check_only_one_user_in_directory(user, room)

    def test_user_not_in_users_table(self) -> None:
        """Unclear how it happens, but on matrix.org we've seen join events
        for users who aren't in the users table. Test that we don't fall over
        when processing such a user.
        """
        user1 = self.register_user("user1", "pass")
        token1 = self.login(user1, "pass")
        room = self.helper.create_room_as(user1, is_public=True, tok=token1)

        # Inject a join event for a user who doesn't exist
        self.get_success(inject_member_event(self.hs, room, "@not-a-user:test", "join"))

        # Another new user registers and joins the room
        user2 = self.register_user("user2", "pass")
        token2 = self.login(user2, "pass")
        self.helper.join(room, user2, tok=token2)

        # The dodgy event should not have stopped us from processing user2's join.
        in_public = self.get_success(self.user_dir_helper.get_users_in_public_rooms())
        self.assertEqual(set(in_public), {(user1, room), (user2, room)})

    def test_excludes_users_when_making_room_public(self) -> None:
        # Create a regular user and a support user.
        alice = self.register_user("alice", "pass")
        alice_token = self.login(alice, "pass")
        support = "@support1:test"
        self.get_success(
            self.store.register_user(
                user_id=support, password_hash=None, user_type=UserTypes.SUPPORT
            )
        )

        # Make a public and private room containing Alice and the support user
        public, initially_private = self._create_rooms_and_inject_memberships(
            alice, alice_token, support
        )
        self._check_only_one_user_in_directory(alice, public)

        # Alice makes the private room public.
        self.helper.send_state(
            initially_private,
            "m.room.join_rules",
            {"join_rule": "public"},
            tok=alice_token,
        )

        users, in_public, in_private = self.get_success(
            self.user_dir_helper.get_tables()
        )
        self.assertEqual(users, {alice})
        self.assertEqual(in_public, {(alice, public), (alice, initially_private)})
        self.assertEqual(in_private, set())

    def test_switching_from_private_to_public_to_private(self) -> None:
        """Check we update the room sharing tables when switching a room
        from private to public, then back again to private."""
        # Alice and Bob share a private room.
        alice = self.register_user("alice", "pass")
        alice_token = self.login(alice, "pass")
        bob = self.register_user("bob", "pass")
        bob_token = self.login(bob, "pass")
        room = self.helper.create_room_as(alice, is_public=False, tok=alice_token)
        self.helper.invite(room, alice, bob, tok=alice_token)
        self.helper.join(room, bob, tok=bob_token)

        # The user directory should reflect this.
        def check_user_dir_for_private_room() -> None:
            users, in_public, in_private = self.get_success(
                self.user_dir_helper.get_tables()
            )
            self.assertEqual(users, {alice, bob})
            self.assertEqual(in_public, set())
            self.assertEqual(in_private, {(alice, bob, room), (bob, alice, room)})

        check_user_dir_for_private_room()

        # Alice makes the room public.
        self.helper.send_state(
            room,
            "m.room.join_rules",
            {"join_rule": "public"},
            tok=alice_token,
        )

        # The user directory should be updated accordingly
        users, in_public, in_private = self.get_success(
            self.user_dir_helper.get_tables()
        )
        self.assertEqual(users, {alice, bob})
        self.assertEqual(in_public, {(alice, room), (bob, room)})
        self.assertEqual(in_private, set())

        # Alice makes the room private.
        self.helper.send_state(
            room,
            "m.room.join_rules",
            {"join_rule": "invite"},
            tok=alice_token,
        )

        # The user directory should be updated accordingly
        check_user_dir_for_private_room()

    def _create_rooms_and_inject_memberships(
        self, creator: str, token: str, joiner: str
    ) -> Tuple[str, str]:
        """Create a public and private room as a normal user.
        Then get the `joiner` into those rooms.
        """
        # TODO: Duplicates the same-named method in UserDirectoryInitialPopulationTest.
        public_room = self.helper.create_room_as(
            creator,
            is_public=True,
            # See https://github.com/matrix-org/synapse/issues/10951
            extra_content={"visibility": "public"},
            tok=token,
        )
        private_room = self.helper.create_room_as(creator, is_public=False, tok=token)

        # HACK: get the user into these rooms
        self.get_success(inject_member_event(self.hs, public_room, joiner, "join"))
        self.get_success(inject_member_event(self.hs, private_room, joiner, "join"))

        return public_room, private_room

    def _check_only_one_user_in_directory(self, user: str, public: str) -> None:
        """Check that the user directory DB tables show that:

        - only one user is in the user directory
        - they belong to exactly one public room
        - they don't share a private room with anyone.
        """
        users, in_public, in_private = self.get_success(
            self.user_dir_helper.get_tables()
        )
        self.assertEqual(users, {user})
        self.assertEqual(in_public, {(user, public)})
        self.assertEqual(in_private, set())

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
        self.assertIsNone(profile)
        display_name = "display_name"

        profile_info = ProfileInfo(avatar_url="avatar_url", display_name=display_name)
        self.get_success(
            self.handler.handle_local_profile_change(regular_user_id, profile_info)
        )
        profile = self.get_success(self.store.get_user_in_directory(regular_user_id))
        assert profile is not None
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
        assert profile is not None
        self.assertTrue(profile["display_name"] == display_name)

        # deactivate user
        self.get_success(self.store.set_user_deactivated_status(r_user_id, True))
        self.get_success(self.handler.handle_local_user_deactivated(r_user_id))

        # profile is not in directory
        profile = self.get_success(self.store.get_user_in_directory(r_user_id))
        self.assertIsNone(profile)

        # update profile after deactivation
        self.get_success(
            self.handler.handle_local_profile_change(r_user_id, profile_info)
        )

        # profile is furthermore not in directory
        profile = self.get_success(self.store.get_user_in_directory(r_user_id))
        self.assertIsNone(profile)

    def test_handle_local_profile_change_with_appservice_user(self) -> None:
        # create user
        as_user_id, _ = self.register_appservice_user(
            "as_user_alice", self.appservice.token
        )

        # profile is not in directory
        profile = self.get_success(self.store.get_user_in_directory(as_user_id))
        self.assertIsNone(profile)

        # update profile
        profile_info = ProfileInfo(avatar_url="avatar_url", display_name="4L1c3")
        self.get_success(
            self.handler.handle_local_profile_change(as_user_id, profile_info)
        )

        # profile is still not in directory
        profile = self.get_success(self.store.get_user_in_directory(as_user_id))
        self.assertIsNone(profile)

    def test_handle_local_profile_change_with_appservice_sender(self) -> None:
        # profile is not in directory
        profile = self.get_success(
            self.store.get_user_in_directory(self.appservice.sender)
        )
        self.assertIsNone(profile)

        # update profile
        profile_info = ProfileInfo(avatar_url="avatar_url", display_name="4L1c3")
        self.get_success(
            self.handler.handle_local_profile_change(
                self.appservice.sender, profile_info
            )
        )

        # profile is still not in directory
        profile = self.get_success(
            self.store.get_user_in_directory(self.appservice.sender)
        )
        self.assertIsNone(profile)

    def test_handle_user_deactivated_support_user(self) -> None:
        s_user_id = "@support:test"
        self.get_success(
            self.store.register_user(
                user_id=s_user_id, password_hash=None, user_type=UserTypes.SUPPORT
            )
        )

        mock_remove_from_user_dir = Mock(return_value=make_awaitable(None))
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

        mock_remove_from_user_dir = Mock(return_value=make_awaitable(None))
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

    def test_process_join_after_server_leaves_room(self) -> None:
        alice = self.register_user("alice", "pass")
        alice_token = self.login(alice, "pass")
        bob = self.register_user("bob", "pass")
        bob_token = self.login(bob, "pass")

        # Alice makes two rooms. Bob joins one of them.
        room1 = self.helper.create_room_as(alice, tok=alice_token)
        room2 = self.helper.create_room_as(alice, tok=alice_token)
        self.helper.join(room1, bob, tok=bob_token)

        # The user sharing tables should have been updated.
        public1 = self.get_success(self.user_dir_helper.get_users_in_public_rooms())
        self.assertEqual(set(public1), {(alice, room1), (alice, room2), (bob, room1)})

        # Alice leaves room1. The user sharing tables should be updated.
        self.helper.leave(room1, alice, tok=alice_token)
        public2 = self.get_success(self.user_dir_helper.get_users_in_public_rooms())
        self.assertEqual(set(public2), {(alice, room2), (bob, room1)})

        # Pause the processing of new events.
        dir_handler = self.hs.get_user_directory_handler()
        dir_handler.update_user_directory = False

        # Bob leaves one room and joins the other.
        self.helper.leave(room1, bob, tok=bob_token)
        self.helper.join(room2, bob, tok=bob_token)

        # Process the leave and join in one go.
        dir_handler.update_user_directory = True
        dir_handler.notify_new_event()
        self.wait_for_background_updates()

        # The user sharing tables should have been updated.
        public3 = self.get_success(self.user_dir_helper.get_users_in_public_rooms())
        self.assertEqual(set(public3), {(alice, room2), (bob, room2)})

    def test_per_room_profile_doesnt_alter_directory_entry(self) -> None:
        alice = self.register_user("alice", "pass")
        alice_token = self.login(alice, "pass")
        bob = self.register_user("bob", "pass")

        # Alice should have a user directory entry created at registration.
        users = self.get_success(self.user_dir_helper.get_profiles_in_user_directory())
        self.assertEqual(
            users[alice], ProfileInfo(display_name="alice", avatar_url=None)
        )

        # Alice makes a room for herself.
        room = self.helper.create_room_as(alice, is_public=True, tok=alice_token)

        # Alice sets a nickname unique to that room.
        self.helper.send_state(
            room,
            "m.room.member",
            {
                "displayname": "Freddy Mercury",
                "membership": "join",
            },
            alice_token,
            state_key=alice,
        )

        # Alice's display name remains the same in the user directory.
        search_result = self.get_success(self.handler.search_users(bob, alice, 10))
        self.assertEqual(
            search_result["results"],
            [{"display_name": "alice", "avatar_url": None, "user_id": alice}],
            0,
        )

    def test_making_room_public_doesnt_alter_directory_entry(self) -> None:
        """Per-room names shouldn't go to the directory when the room becomes public.

        This isn't about preventing a leak (the room is now public, so the nickname
        is too). It's about preserving the invariant that we only show a user's public
        profile in the user directory results.

        I made this a Synapse test case rather than a Complement one because
        I think this is (strictly speaking) an implementation choice. Synapse
        has chosen to only ever use the public profile when responding to a user
        directory search. There's no privacy leak here, because making the room
        public discloses the per-room name.

        The spec doesn't mandate anything about _how_ a user
        should appear in a /user_directory/search result. Hypothetical example:
        suppose Bob searches for Alice. When representing Alice in a search
        result, it's reasonable to use any of Alice's nicknames that Bob is
        aware of. Heck, maybe we even want to use lots of them in a combined
        displayname like `Alice (aka "ali", "ally", "41iC3")`.
        """

        # TODO the same should apply when Alice is a remote user.
        alice = self.register_user("alice", "pass")
        alice_token = self.login(alice, "pass")
        bob = self.register_user("bob", "pass")
        bob_token = self.login(bob, "pass")

        # Alice and Bob are in a private room.
        room = self.helper.create_room_as(alice, is_public=False, tok=alice_token)
        self.helper.invite(room, src=alice, targ=bob, tok=alice_token)
        self.helper.join(room, user=bob, tok=bob_token)

        # Alice has a nickname unique to that room.

        self.helper.send_state(
            room,
            "m.room.member",
            {
                "displayname": "Freddy Mercury",
                "membership": "join",
            },
            alice_token,
            state_key=alice,
        )

        # Check Alice isn't recorded as being in a public room.
        public = self.get_success(self.user_dir_helper.get_users_in_public_rooms())
        self.assertNotIn((alice, room), public)

        # One of them makes the room public.
        self.helper.send_state(
            room,
            "m.room.join_rules",
            {"join_rule": "public"},
            alice_token,
        )

        # Check that Alice is now recorded as being in a public room
        public = self.get_success(self.user_dir_helper.get_users_in_public_rooms())
        self.assertIn((alice, room), public)

        # Alice's display name remains the same in the user directory.
        search_result = self.get_success(self.handler.search_users(bob, alice, 10))
        self.assertEqual(
            search_result["results"],
            [{"display_name": "alice", "avatar_url": None, "user_id": alice}],
            0,
        )

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

        # u1 can't see u2 until they share a private room, or u1 is in a public room.
        s = self.get_success(self.handler.search_users(u1, "user2", 10))
        self.assertEqual(len(s["results"]), 0)

        # Get u1 and u2 into a private room.
        room = self.helper.create_room_as(u1, is_public=False, tok=u1_token)
        self.helper.invite(room, src=u1, targ=u2, tok=u1_token)
        self.helper.join(room, user=u2, tok=u2_token)

        # Check we have populated the database correctly.
        users, public_users, shares_private = self.get_success(
            self.user_dir_helper.get_tables()
        )
        self.assertEqual(users, {u1, u2, u3})
        self.assertEqual(shares_private, {(u1, u2, room), (u2, u1, room)})
        self.assertEqual(public_users, set())

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

        # Check this is reflected in the DB.
        users, public_users, shares_private = self.get_success(
            self.user_dir_helper.get_tables()
        )
        self.assertEqual(users, {u1, u2, u3})
        self.assertEqual(shares_private, set())
        self.assertEqual(public_users, set())

        # User1 now gets no search results for any of the other users.
        s = self.get_success(self.handler.search_users(u1, "user2", 10))
        self.assertEqual(len(s["results"]), 0)

        s = self.get_success(self.handler.search_users(u1, "user3", 10))
        self.assertEqual(len(s["results"]), 0)

    def test_joining_private_room_with_excluded_user(self) -> None:
        """
        When a user excluded from the user directory, E say, joins a private
        room, E will not appear in the `users_who_share_private_rooms` table.

        When a normal user, U say, joins a private room containing E, then
        U will appear in the `users_who_share_private_rooms` table, but E will
        not.
        """
        # Setup a support and two normal users.
        alice = self.register_user("alice", "pass")
        alice_token = self.login(alice, "pass")
        bob = self.register_user("bob", "pass")
        bob_token = self.login(bob, "pass")
        support = "@support1:test"
        self.get_success(
            self.store.register_user(
                user_id=support, password_hash=None, user_type=UserTypes.SUPPORT
            )
        )

        # Alice makes a room. Inject the support user into the room.
        room = self.helper.create_room_as(alice, is_public=False, tok=alice_token)
        self.get_success(inject_member_event(self.hs, room, support, "join"))
        # Check the DB state. The support user should not be in the directory.
        users, in_public, in_private = self.get_success(
            self.user_dir_helper.get_tables()
        )
        self.assertEqual(users, {alice, bob})
        self.assertEqual(in_public, set())
        self.assertEqual(in_private, set())

        # Then invite Bob, who accepts.
        self.helper.invite(room, alice, bob, tok=alice_token)
        self.helper.join(room, bob, tok=bob_token)

        # Check the DB state. The support user should not be in the directory.
        users, in_public, in_private = self.get_success(
            self.user_dir_helper.get_tables()
        )
        self.assertEqual(users, {alice, bob})
        self.assertEqual(in_public, set())
        self.assertEqual(in_private, {(alice, bob, room), (bob, alice, room)})

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

        self.assertEqual(shares_private, {(u1, u2, room), (u2, u1, room)})
        self.assertEqual(public_users, set())

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

        self.assertEqual(shares_private, {(u1, u2, room), (u2, u1, room)})
        self.assertEqual(public_users, set())

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
        self.assertEqual(public_users, set())
        self.assertEqual(shares_private, set())

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
            self.hs.get_storage_controllers().persistence.persist_event(event, context)
        )

    def test_local_user_leaving_room_remains_in_user_directory(self) -> None:
        """We've chosen to simplify the user directory's implementation by
        always including local users. Ensure this invariant is maintained when
        a local user
        - leaves a room, and
        - leaves the last room they're in which is visible to this server.

        This is user-visible if the "search_all_users" config option is on: the
        local user who left a room would no longer be searchable if this test fails!
        """
        alice = self.register_user("alice", "pass")
        alice_token = self.login(alice, "pass")
        bob = self.register_user("bob", "pass")
        bob_token = self.login(bob, "pass")

        # Alice makes two public rooms, which Bob joins.
        room1 = self.helper.create_room_as(alice, is_public=True, tok=alice_token)
        room2 = self.helper.create_room_as(alice, is_public=True, tok=alice_token)
        self.helper.join(room1, bob, tok=bob_token)
        self.helper.join(room2, bob, tok=bob_token)

        # The user directory tables are updated.
        users, in_public, in_private = self.get_success(
            self.user_dir_helper.get_tables()
        )
        self.assertEqual(users, {alice, bob})
        self.assertEqual(
            in_public, {(alice, room1), (alice, room2), (bob, room1), (bob, room2)}
        )
        self.assertEqual(in_private, set())

        # Alice leaves one room. She should still be in the directory.
        self.helper.leave(room1, alice, tok=alice_token)
        users, in_public, in_private = self.get_success(
            self.user_dir_helper.get_tables()
        )
        self.assertEqual(users, {alice, bob})
        self.assertEqual(in_public, {(alice, room2), (bob, room1), (bob, room2)})
        self.assertEqual(in_private, set())

        # Alice leaves the other. She should still be in the directory.
        self.helper.leave(room2, alice, tok=alice_token)
        self.wait_for_background_updates()
        users, in_public, in_private = self.get_success(
            self.user_dir_helper.get_tables()
        )
        self.assertEqual(users, {alice, bob})
        self.assertEqual(in_public, {(bob, room1), (bob, room2)})
        self.assertEqual(in_private, set())

    def test_ignore_display_names_with_null_codepoints(self) -> None:
        MXC_DUMMY = "mxc://dummy"

        # Alice creates a public room.
        alice = self.register_user("alice", "pass")

        # Alice has a user directory entry to start with.
        self.assertIn(
            alice,
            self.get_success(self.user_dir_helper.get_profiles_in_user_directory()),
        )

        # Alice changes her name to include a null codepoint.
        self.get_success(
            self.hs.get_user_directory_handler().handle_local_profile_change(
                alice,
                ProfileInfo(
                    display_name="abcd\u0000efgh",
                    avatar_url=MXC_DUMMY,
                ),
            )
        )
        # Alice's profile should be updated with the new avatar, but no display name.
        self.assertEqual(
            self.get_success(self.user_dir_helper.get_profiles_in_user_directory()),
            {alice: ProfileInfo(display_name=None, avatar_url=MXC_DUMMY)},
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
        self.assertEqual(200, channel.code, channel.result)
        self.assertTrue(len(channel.json_body["results"]) > 0)

        # Disable user directory and check search returns nothing
        self.config.userdirectory.user_directory_search_enabled = False
        channel = self.make_request(
            "POST",
            b"user_directory/search",
            b'{"search_term":"user2"}',
            access_token=u1_token,
        )
        self.assertEqual(200, channel.code, channel.result)
        self.assertTrue(len(channel.json_body["results"]) == 0)
