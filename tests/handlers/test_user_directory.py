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
from mock import Mock

from synapse.api.constants import UserTypes
from synapse.rest.client.v1 import admin, login, room
from synapse.storage.roommember import ProfileInfo

from tests import unittest


class UserDirectoryTestCase(unittest.HomeserverTestCase):
    """
    Tests the UserDirectoryHandler.
    """

    servlets = [
        login.register_servlets,
        admin.register_servlets,
        room.register_servlets,
    ]

    def make_homeserver(self, reactor, clock):

        config = self.default_config()
        config.update_user_directory = True
        return self.setup_test_homeserver(config=config)

    def prepare(self, reactor, clock, hs):
        hs.config.update_user_directory = True
        self.store = hs.get_datastore()
        self.handler = hs.get_user_directory_handler()

    def test_handle_local_profile_change_with_support_user(self):
        support_user_id = "@support:test"
        self.get_success(
            self.store.register(
                user_id=support_user_id,
                token="123",
                password_hash=None,
                user_type=UserTypes.SUPPORT,
            )
        )

        self.get_success(
            self.handler.handle_local_profile_change(support_user_id, None)
        )
        profile = self.get_success(self.store.get_user_in_directory(support_user_id))
        self.assertTrue(profile is None)
        display_name = 'display_name'

        profile_info = ProfileInfo(avatar_url='avatar_url', display_name=display_name)
        regular_user_id = '@regular:test'
        self.get_success(
            self.handler.handle_local_profile_change(regular_user_id, profile_info)
        )
        profile = self.get_success(self.store.get_user_in_directory(regular_user_id))
        self.assertTrue(profile['display_name'] == display_name)

    def test_handle_user_deactivated_support_user(self):
        s_user_id = "@support:test"
        self.get_success(
            self.store.register(
                user_id=s_user_id,
                token="123",
                password_hash=None,
                user_type=UserTypes.SUPPORT,
            )
        )

        self.store.remove_from_user_dir = Mock()
        self.store.remove_from_user_in_public_room = Mock()
        self.get_success(self.handler.handle_user_deactivated(s_user_id))
        self.store.remove_from_user_dir.not_called()
        self.store.remove_from_user_in_public_room.not_called()

    def test_handle_user_deactivated_regular_user(self):
        r_user_id = "@regular:test"
        self.get_success(
            self.store.register(user_id=r_user_id, token="123", password_hash=None)
        )
        self.store.remove_from_user_dir = Mock()
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
        shares_public = self.get_users_who_share_public_rooms()
        shares_private = self.get_users_who_share_private_rooms()

        self.assertEqual(shares_public, [])
        self.assertEqual(
            self._compress_shared(shares_private), set([(u1, u2, room), (u2, u1, room)])
        )

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
        shares_public = self.get_users_who_share_public_rooms()
        shares_private = self.get_users_who_share_private_rooms()

        self.assertEqual(shares_public, [])
        self.assertEqual(self._compress_shared(shares_private), set())

        # User1 now gets no search results for any of the other users.
        s = self.get_success(self.handler.search_users(u1, "user2", 10))
        self.assertEqual(len(s["results"]), 0)

        s = self.get_success(self.handler.search_users(u1, "user3", 10))
        self.assertEqual(len(s["results"]), 0)

    def _compress_shared(self, shared):
        """
        Compress a list of users who share rooms dicts to a list of tuples.
        """
        r = set()
        for i in shared:
            r.add((i["user_id"], i["other_user_id"], i["room_id"]))
        return r

    def get_users_who_share_public_rooms(self):
        return self.get_success(
            self.store._simple_select_list(
                "users_who_share_public_rooms",
                None,
                ["user_id", "other_user_id", "room_id"],
            )
        )

    def get_users_who_share_private_rooms(self):
        return self.get_success(
            self.store._simple_select_list(
                "users_who_share_private_rooms",
                None,
                ["user_id", "other_user_id", "room_id"],
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

        shares_public = self.get_users_who_share_public_rooms()
        shares_private = self.get_users_who_share_private_rooms()

        self.assertEqual(shares_private, [])
        self.assertEqual(shares_public, [])

        # Reset the handled users caches
        self.handler.initially_handled_users = set()

        # Do the initial population
        d = self.handler._do_initial_spam()

        # This takes a while, so pump it a bunch of times to get through the
        # sleep delays
        for i in range(10):
            self.pump(1)

        self.get_success(d)

        shares_public = self.get_users_who_share_public_rooms()
        shares_private = self.get_users_who_share_private_rooms()

        # User 1 and User 2 share public rooms
        self.assertEqual(
            self._compress_shared(shares_public), set([(u1, u2, room), (u2, u1, room)])
        )

        # User 1 and User 3 share private rooms
        self.assertEqual(
            self._compress_shared(shares_private),
            set([(u1, u3, private_room), (u3, u1, private_room)]),
        )

    def test_search_all_users(self):
        """
        Search all users = True means that a user does not have to share a
        private room with the searching user or be in a public room to be search
        visible.
        """
        self.hs.config.user_directory_search_all_users = True

        u1 = self.register_user("user1", "pass")
        u1_token = self.login(u1, "pass")
        u2 = self.register_user("user2", "pass")
        u2_token = self.login(u2, "pass")
        u3 = self.register_user("user3", "pass")

        # User 1 and User 2 join a room. User 3 never does.
        room = self.helper.create_room_as(u1, is_public=True, tok=u1_token)
        self.helper.invite(room, src=u1, targ=u2, tok=u1_token)
        self.helper.join(room, user=u2, tok=u2_token)

        self.get_success(self.store.update_user_directory_stream_pos(None))
        self.get_success(self.store.delete_all_from_user_dir())

        # Reset the handled users caches
        self.handler.initially_handled_users = set()

        # Do the initial population
        d = self.handler._do_initial_spam()

        # This takes a while, so pump it a bunch of times to get through the
        # sleep delays
        for i in range(10):
            self.pump(1)

        self.get_success(d)

        # Despite not sharing a room, search_all_users means we get a search
        # result.
        s = self.get_success(self.handler.search_users(u1, u3, 10))
        self.assertEqual(len(s["results"]), 1)
