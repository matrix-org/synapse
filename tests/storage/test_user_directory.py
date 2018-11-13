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

from twisted.internet import defer

from synapse.api.constants import UserTypes
from synapse.storage import UserDirectoryStore
from synapse.storage.roommember import ProfileInfo

from tests import unittest
from tests.utils import setup_test_homeserver

ALICE = "@alice:a"
BOB = "@bob:b"
BOBBY = "@bobby:a"
ROOM = "!room:id"


class UserDirectoryStoreTestCase(unittest.TestCase):
    @defer.inlineCallbacks
    def setUp(self):
        self.hs = yield setup_test_homeserver(self.addCleanup)
        self.store = self.hs.get_datastore()
        # self.store = UserDirectoryStore(self.hs.get_db_conn(), self.hs)

        # alice and bob are both in !room_id. bobby is not but shares
        # a homeserver with alice.
        yield self.store.add_profiles_to_user_dir(
            "!room:id",
            {
                ALICE: ProfileInfo(None, "alice"),
                BOB: ProfileInfo(None, "bob"),
                BOBBY: ProfileInfo(None, "bobby"),
            },
        )
        yield self.store.add_users_to_public_room(ROOM, [ALICE, BOB])
        yield self.store.add_users_who_share_room(
            "!room:id", False, ((ALICE, BOB), (BOB, ALICE))
        )

    @defer.inlineCallbacks
    def test_search_user_dir(self):
        # normally when alice searches the directory she should just find
        # bob because bobby doesn't share a room with her.
        r = yield self.store.search_user_dir(ALICE, "bob", 10)
        self.assertFalse(r["limited"])
        self.assertEqual(1, len(r["results"]))
        self.assertDictEqual(
            r["results"][0], {"user_id": BOB, "display_name": "bob", "avatar_url": None}
        )

    @defer.inlineCallbacks
    def test_search_user_dir_all_users(self):
        self.hs.config.user_directory_search_all_users = True
        try:
            r = yield self.store.search_user_dir(ALICE, "bob", 10)
            self.assertFalse(r["limited"])
            self.assertEqual(2, len(r["results"]))
            self.assertDictEqual(
                r["results"][0],
                {"user_id": BOB, "display_name": "bob", "avatar_url": None},
            )
            self.assertDictEqual(
                r["results"][1],
                {"user_id": BOBBY, "display_name": "bobby", "avatar_url": None},
            )
        finally:
            self.hs.config.user_directory_search_all_users = False

    # @defer.inlineCallbacks
    # def test_cannot_add_support_user_to_directory(self):
    #     self.hs.config.user_directory_search_all_users = True
    #     SUPPORT_USER = "@support:test"
    #     SUPPOER_USER_SCREEN_NAME = "Support"
    #
    #     yield self.store.register(user_id=SUPPORT_USER, token="123",
    #                               password_hash=None,
    #                               user_type=UserTypes.SUPPORT)
    #     yield self.store.register(user_id=ALICE, token="456", password_hash=None)
    #
    #     yield self.store.add_profiles_to_user_dir(
    #         ROOM,
    #         {SUPPORT_USER: ProfileInfo(None, SUPPOER_USER_SCREEN_NAME)},
    #     )
    #     yield self.store.add_users_to_public_room(ROOM, [SUPPORT_USER])
    #     yield self.store.add_users_who_share_room(
    #         ROOM, False, ((ALICE, SUPPORT_USER),)
    #     )
    #
    #     r = yield self.store.search_user_dir(ALICE, SUPPOER_USER_SCREEN_NAME, 10)
    #     self.assertFalse(r["limited"])
    #     self.assertEqual(0, len(r["results"]))
    #
    #     # Check that enabled support user does not prevent all users being added
    #     r = yield self.store.search_user_dir(ALICE, ALICE, 10)
    #     self.assertFalse(r["limited"])
    #     self.assertEqual(1, len(r["results"]))
    #
    #     yield self.store.update_user_in_user_dir(SUPPORT_USER, ROOM)
    #     yield self.store.update_profile_in_user_dir(
    #         SUPPORT_USER, SUPPOER_USER_SCREEN_NAME, None, ROOM
    #     )
    #     yield self.store.update_user_in_public_user_list(SUPPORT_USER, ROOM)
    #
    #     r = yield self.store.search_user_dir(ALICE, SUPPOER_USER_SCREEN_NAME, 10)
    #     self.assertFalse(r["limited"])
    #     self.assertEqual(0, len(r["results"]))
    #
    #     r = yield self.store.get_user_in_directory(SUPPORT_USER)
    #     self.assertEqual(r, None)
    #
    #     r = yield self.store.get_user_in_public_room(SUPPORT_USER)
    #     self.assertEqual(r, None)
