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
from typing import Dict, Tuple

from mock import Mock

from twisted.internet import defer

import synapse.rest.admin
from synapse.api.constants import EventTypes, RoomEncryptionAlgorithms, UserTypes
from synapse.config import ConfigError
from synapse.module_api import ModuleApi
from synapse.rest.client.v1 import login, room
from synapse.rest.client.v2_alpha import user_directory
from synapse.storage.engines import BaseDatabaseEngine
from synapse.storage.roommember import ProfileInfo

from tests import unittest
from tests.unittest import override_config


class UserDirectoryTestCase(unittest.HomeserverTestCase):
    """
    Tests the UserDirectoryHandler.
    """

    servlets = [
        login.register_servlets,
        synapse.rest.admin.register_servlets_for_client_rest_resource,
        room.register_servlets,
    ]

    def make_homeserver(self, reactor, clock):

        config = self.default_config()
        config["update_user_directory"] = True
        return self.setup_test_homeserver(config=config)

    def prepare(self, reactor, clock, hs):
        self.store = hs.get_datastore()
        self.handler = hs.get_user_directory_handler()

    def test_handle_local_profile_change_with_support_user(self):
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
            self.handler.handle_local_profile_change(support_user_id, None)
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

    def test_handle_local_profile_change_with_deactivated_user(self):
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
        self.get_success(self.handler.handle_user_deactivated(r_user_id))

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

    def test_handle_user_deactivated_support_user(self):
        s_user_id = "@support:test"
        self.get_success(
            self.store.register_user(
                user_id=s_user_id, password_hash=None, user_type=UserTypes.SUPPORT
            )
        )

        self.store.remove_from_user_dir = Mock(return_value=defer.succeed(None))
        self.get_success(self.handler.handle_user_deactivated(s_user_id))
        self.store.remove_from_user_dir.not_called()

    def test_handle_user_deactivated_regular_user(self):
        r_user_id = "@regular:test"
        self.get_success(
            self.store.register_user(user_id=r_user_id, password_hash=None)
        )
        self.store.remove_from_user_dir = Mock(return_value=defer.succeed(None))
        self.get_success(self.handler.handle_user_deactivated(r_user_id))
        self.store.remove_from_user_dir.called_once_with(r_user_id)

    def test_private_room(self):
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
        shares_private = self.get_users_who_share_private_rooms()
        public_users = self.get_users_in_public_rooms()

        self.assertEqual(
            self._compress_shared(shares_private), {(u1, u2, room), (u2, u1, room)}
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
        shares_private = self.get_users_who_share_private_rooms()
        public_users = self.get_users_in_public_rooms()

        self.assertEqual(self._compress_shared(shares_private), set())
        self.assertEqual(public_users, [])

        # User1 now gets no search results for any of the other users.
        s = self.get_success(self.handler.search_users(u1, "user2", 10))
        self.assertEqual(len(s["results"]), 0)

        s = self.get_success(self.handler.search_users(u1, "user3", 10))
        self.assertEqual(len(s["results"]), 0)

    @override_config({"encryption_enabled_by_default_for_room_type": "all"})
    def test_encrypted_by_default_config_option_all(self):
        """Tests that invite-only and non-invite-only rooms have encryption enabled by
        default when the config option encryption_enabled_by_default_for_room_type is "all".
        """
        # Create a user
        user = self.register_user("user", "pass")
        user_token = self.login(user, "pass")

        # Create an invite-only room as that user
        room_id = self.helper.create_room_as(user, is_public=False, tok=user_token)

        # Check that the room has an encryption state event
        event_content = self.helper.get_state(
            room_id=room_id, event_type=EventTypes.RoomEncryption, tok=user_token,
        )
        self.assertEqual(event_content, {"algorithm": RoomEncryptionAlgorithms.DEFAULT})

        # Create a non invite-only room as that user
        room_id = self.helper.create_room_as(user, is_public=True, tok=user_token)

        # Check that the room has an encryption state event
        event_content = self.helper.get_state(
            room_id=room_id, event_type=EventTypes.RoomEncryption, tok=user_token,
        )
        self.assertEqual(event_content, {"algorithm": RoomEncryptionAlgorithms.DEFAULT})

    @override_config({"encryption_enabled_by_default_for_room_type": "invite"})
    def test_encrypted_by_default_config_option_invite(self):
        """Tests that only new, invite-only rooms have encryption enabled by default when
        the config option encryption_enabled_by_default_for_room_type is "invite".
        """
        # Create a user
        user = self.register_user("user", "pass")
        user_token = self.login(user, "pass")

        # Create an invite-only room as that user
        room_id = self.helper.create_room_as(user, is_public=False, tok=user_token)

        # Check that the room has an encryption state event
        event_content = self.helper.get_state(
            room_id=room_id, event_type=EventTypes.RoomEncryption, tok=user_token,
        )
        self.assertEqual(event_content, {"algorithm": RoomEncryptionAlgorithms.DEFAULT})

        # Create a non invite-only room as that user
        room_id = self.helper.create_room_as(user, is_public=True, tok=user_token)

        # Check that the room does not have an encryption state event
        self.helper.get_state(
            room_id=room_id,
            event_type=EventTypes.RoomEncryption,
            tok=user_token,
            expect_code=404,
        )

    @override_config({"encryption_enabled_by_default_for_room_type": "off"})
    def test_encrypted_by_default_config_option_off(self):
        """Tests that neither new invite-only nor non-invite-only rooms have encryption
        enabled by default when the config option
        encryption_enabled_by_default_for_room_type is "off".
        """
        # Create a user
        user = self.register_user("user", "pass")
        user_token = self.login(user, "pass")

        # Create an invite-only room as that user
        room_id = self.helper.create_room_as(user, is_public=False, tok=user_token)

        # Check that the room does not have an encryption state event
        self.helper.get_state(
            room_id=room_id,
            event_type=EventTypes.RoomEncryption,
            tok=user_token,
            expect_code=404,
        )

        # Create a non invite-only room as that user
        room_id = self.helper.create_room_as(user, is_public=True, tok=user_token)

        # Check that the room does not have an encryption state event
        self.helper.get_state(
            room_id=room_id,
            event_type=EventTypes.RoomEncryption,
            tok=user_token,
            expect_code=404,
        )

    def test_spam_checker(self):
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
        shares_private = self.get_users_who_share_private_rooms()
        public_users = self.get_users_in_public_rooms()

        self.assertEqual(
            self._compress_shared(shares_private), {(u1, u2, room), (u2, u1, room)}
        )
        self.assertEqual(public_users, [])

        # We get one search result when searching for user2 by user1.
        s = self.get_success(self.handler.search_users(u1, "user2", 10))
        self.assertEqual(len(s["results"]), 1)

        # Configure a spam checker that does not filter any users.
        spam_checker = self.hs.get_spam_checker()

        class AllowAll:
            async def check_username_for_spam(self, user_profile):
                # Allow all users.
                return False

        spam_checker.spam_checkers = [AllowAll()]

        # The results do not change:
        # We get one search result when searching for user2 by user1.
        s = self.get_success(self.handler.search_users(u1, "user2", 10))
        self.assertEqual(len(s["results"]), 1)

        # Configure a spam checker that filters all users.
        class BlockAll:
            async def check_username_for_spam(self, user_profile):
                # All users are spammy.
                return True

        spam_checker.spam_checkers = [BlockAll()]

        # User1 now gets no search results for any of the other users.
        s = self.get_success(self.handler.search_users(u1, "user2", 10))
        self.assertEqual(len(s["results"]), 0)

    def test_legacy_spam_checker(self):
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
        shares_private = self.get_users_who_share_private_rooms()
        public_users = self.get_users_in_public_rooms()

        self.assertEqual(
            self._compress_shared(shares_private), {(u1, u2, room), (u2, u1, room)}
        )
        self.assertEqual(public_users, [])

        # Configure a spam checker.
        spam_checker = self.hs.get_spam_checker()
        # The spam checker doesn't need any methods, so create a bare object.
        spam_checker.spam_checker = object()

        # We get one search result when searching for user2 by user1.
        s = self.get_success(self.handler.search_users(u1, "user2", 10))
        self.assertEqual(len(s["results"]), 1)

    def _compress_shared(self, shared):
        """
        Compress a list of users who share rooms dicts to a list of tuples.
        """
        r = set()
        for i in shared:
            r.add((i["user_id"], i["other_user_id"], i["room_id"]))
        return r

    def get_users_in_public_rooms(self):
        r = self.get_success(
            self.store.db_pool.simple_select_list(
                "users_in_public_rooms", None, ("user_id", "room_id")
            )
        )
        retval = []
        for i in r:
            retval.append((i["user_id"], i["room_id"]))
        return retval

    def get_users_who_share_private_rooms(self):
        return self.get_success(
            self.store.db_pool.simple_select_list(
                "users_who_share_private_rooms",
                None,
                ["user_id", "other_user_id", "room_id"],
            )
        )

    def _add_background_updates(self):
        """
        Add the background updates we need to run.
        """
        # Ugh, have to reset this flag
        self.store.db_pool.updates._all_done = False

        self.get_success(
            self.store.db_pool.simple_insert(
                "background_updates",
                {
                    "update_name": "populate_user_directory_createtables",
                    "progress_json": "{}",
                },
            )
        )
        self.get_success(
            self.store.db_pool.simple_insert(
                "background_updates",
                {
                    "update_name": "populate_user_directory_process_rooms",
                    "progress_json": "{}",
                    "depends_on": "populate_user_directory_createtables",
                },
            )
        )
        self.get_success(
            self.store.db_pool.simple_insert(
                "background_updates",
                {
                    "update_name": "populate_user_directory_process_users",
                    "progress_json": "{}",
                    "depends_on": "populate_user_directory_process_rooms",
                },
            )
        )
        self.get_success(
            self.store.db_pool.simple_insert(
                "background_updates",
                {
                    "update_name": "populate_user_directory_cleanup",
                    "progress_json": "{}",
                    "depends_on": "populate_user_directory_process_users",
                },
            )
        )

    def test_initial(self):
        """
        The user directory's initial handler correctly updates the search tables.
        """
        u1 = self.register_user("user1", "pass")
        u1_token = self.login(u1, "pass")
        u2 = self.register_user("user2", "pass")
        u2_token = self.login(u2, "pass")
        u3 = self.register_user("user3", "pass")
        u3_token = self.login(u3, "pass")

        room = self.helper.create_room_as(u1, is_public=True, tok=u1_token)
        self.helper.invite(room, src=u1, targ=u2, tok=u1_token)
        self.helper.join(room, user=u2, tok=u2_token)

        private_room = self.helper.create_room_as(u1, is_public=False, tok=u1_token)
        self.helper.invite(private_room, src=u1, targ=u3, tok=u1_token)
        self.helper.join(private_room, user=u3, tok=u3_token)

        self.get_success(self.store.update_user_directory_stream_pos(None))
        self.get_success(self.store.delete_all_from_user_dir())

        shares_private = self.get_users_who_share_private_rooms()
        public_users = self.get_users_in_public_rooms()

        # Nothing updated yet
        self.assertEqual(shares_private, [])
        self.assertEqual(public_users, [])

        # Do the initial population of the user directory via the background update
        self._add_background_updates()

        while not self.get_success(
            self.store.db_pool.updates.has_completed_background_updates()
        ):
            self.get_success(
                self.store.db_pool.updates.do_next_background_update(100), by=0.1
            )

        shares_private = self.get_users_who_share_private_rooms()
        public_users = self.get_users_in_public_rooms()

        # User 1 and User 2 are in the same public room
        self.assertEqual(set(public_users), {(u1, room), (u2, room)})

        # User 1 and User 3 share private rooms
        self.assertEqual(
            self._compress_shared(shares_private),
            {(u1, u3, private_room), (u3, u1, private_room)},
        )

    def test_initial_share_all_users(self):
        """
        Search all users = True means that a user does not have to share a
        private room with the searching user or be in a public room to be search
        visible.
        """
        self.handler.search_all_users = True
        self.hs.config.user_directory_search_all_users = True

        u1 = self.register_user("user1", "pass")
        self.register_user("user2", "pass")
        u3 = self.register_user("user3", "pass")

        # Wipe the user dir
        self.get_success(self.store.update_user_directory_stream_pos(None))
        self.get_success(self.store.delete_all_from_user_dir())

        # Do the initial population of the user directory via the background update
        self._add_background_updates()

        while not self.get_success(
            self.store.db_pool.updates.has_completed_background_updates()
        ):
            self.get_success(
                self.store.db_pool.updates.do_next_background_update(100), by=0.1
            )

        shares_private = self.get_users_who_share_private_rooms()
        public_users = self.get_users_in_public_rooms()

        # No users share rooms
        self.assertEqual(public_users, [])
        self.assertEqual(self._compress_shared(shares_private), set())

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


class TestUserDirSearchDisabled(unittest.HomeserverTestCase):
    user_id = "@test:test"

    servlets = [
        user_directory.register_servlets,
        room.register_servlets,
        login.register_servlets,
        synapse.rest.admin.register_servlets_for_client_rest_resource,
    ]

    def make_homeserver(self, reactor, clock):
        config = self.default_config()
        config["update_user_directory"] = True
        hs = self.setup_test_homeserver(config=config)

        self.config = hs.config

        return hs

    def test_disabling_room_list(self):
        self.config.user_directory_search_enabled = True

        # First we create a room with another user so that user dir is non-empty
        # for our user
        self.helper.create_room_as(self.user_id)
        u2 = self.register_user("user2", "pass")
        room = self.helper.create_room_as(self.user_id)
        self.helper.join(room, user=u2)

        # Assert user directory is not empty
        channel = self.make_request(
            "POST", b"user_directory/search", b'{"search_term":"user2"}'
        )
        self.assertEquals(200, channel.code, channel.result)
        self.assertTrue(len(channel.json_body["results"]) > 0)

        # Disable user directory and check search returns nothing
        self.config.user_directory_search_enabled = False
        channel = self.make_request(
            "POST", b"user_directory/search", b'{"search_term":"user2"}'
        )
        self.assertEquals(200, channel.code, channel.result)
        self.assertTrue(len(channel.json_body["results"]) == 0)


class UserDirectorySearchTestModule:
    def __init__(self, config: Dict, module_api: ModuleApi):
        self.config = config
        self.user_displayname_to_show_first = self.config[
            "user_displayname_to_show_first"
        ]

        # Ensure an initialised ModuleApi has been passed
        if module_api is None or not isinstance(module_api, ModuleApi):
            raise Exception("Passed module_api is invalid")

    @staticmethod
    def parse_config(config: Dict) -> Dict:
        """Parse the dict provided by the homeserver's config
        Args:
            config: A dictionary containing configuration options for this provider.

        Returns:
            A custom config object for this module.
        """
        if "user_displayname_to_show_first" not in config:
            raise ConfigError("user_displayname_to_show_first is a required field")

        return config

    def get_search_query_ordering(
        self, database_engine_type: BaseDatabaseEngine
    ) -> Tuple[str, Tuple]:
        """Returns the contents of the ORDER BY section of the user directory search
        query.

        Args:
            database_engine_type: The type of database engine that is in use. One of
                those in synapse/storage/engines/*.
                Ex. synapse.storage.engines.PostgresEngine

        Returns:
            A tuple containing:

            * A string that can be placed after ORDER BY in order to influence the
              ordering of results from a user directory search.
            * A tuple containing any extra arguments to provide to the query.
        """
        # Users with a specific display name should get the highest overall rank.
        # Otherwise, we simply order users by their display name lexicographically.
        return (
            """
            display_name = ? DESC,
            display_name ASC
        """,
            (self.user_displayname_to_show_first,),
        )


# A displayname for a user that we expect our custom module to present first in results
test_displayname = "3 Super Special Displayname"


class UserDirectorySearchModuleTestCase(unittest.HomeserverTestCase):
    servlets = [
        synapse.rest.admin.register_servlets,
        user_directory.register_servlets,
    ]

    @override_config(
        {
            "user_directory": {
                "enabled": True,
                "search_all_users": True,
                "user_directory_search_module": {
                    "module": (
                        "tests.handlers.test_user_directory.UserDirectorySearchTestModule"
                    ),
                    "config": {
                        "user_displayname_to_show_first": test_displayname,
                        "test_option": True,
                    },
                },
            }
        }
    )
    def test_parse_config(self):
        """Test that parsing a config produces the expected ModuleConfig object."""
        # Check that our custom module was loaded
        user_dir_search_module = self.hs.get_user_directory_search_module()
        self.assertIsNotNone(user_dir_search_module.custom_module)
        self.assertTrue(
            isinstance(
                user_dir_search_module.custom_module, UserDirectorySearchTestModule
            ),
        )

        # Check that the custom module was configured as expected
        self.assertTrue(user_dir_search_module.custom_module.config["test_option"],)
        self.assertEqual(
            user_dir_search_module.custom_module.user_displayname_to_show_first,
            test_displayname,
        )

    @override_config(
        {
            "user_directory": {
                "enabled": True,
                "search_all_users": True,
                "user_directory_search_module": {
                    "module": (
                        "tests.handlers.test_user_directory.UserDirectorySearchTestModule"
                    ),
                    # Fill the config with options that will influence user dir search results
                    "config": {"user_displayname_to_show_first": test_displayname},
                },
            }
        }
    )
    def test_get_search_query_ordering(self):
        """Tests that implementing UserDirectorySearchModule.get_search_query_ordering
        modifies the ordering of user directory search results
        """
        handler = self.hs.get_user_directory_handler()

        # Create a few users to test the directory with
        user1 = self.register_user(
            "user1", "password", displayname="1 Ordinary Displayname"
        )
        user2 = self.register_user(
            "user2", "password", displayname="2 Normal Displayname"
        )
        user3 = self.register_user("user3", "password", displayname=test_displayname)

        searcher = self.register_user("searcher", "password")

        # Search for the term "user"
        results = self.get_success(handler.search_users(searcher, "user", 20))[
            "results"
        ]

        # Typically we'd expect Synapse to return users in lexicographical order, assuming
        # they have similar User IDs/display names, and profile information.

        # We purposefully don't include a test for ordering without this module as Synapse
        # could change its default user directory ordering at any time.

        # Check that the order of returned results using our module is as we expect,
        # i.e our user with a special display name shows up first (and results after that
        # are simply ordered lexicographically ascending).
        received_user_id_ordering = [result["user_id"] for result in results]
        expected_user_id_ordering = [user3, user1, user2]
        self.assertEqual(received_user_id_ordering, expected_user_id_ordering)
