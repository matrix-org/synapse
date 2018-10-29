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

from synapse.storage import UserDirectoryStore
from synapse.storage.roommember import ProfileInfo

from tests import unittest
from tests.utils import setup_test_homeserver

ALICE = "@alice:a"
BOB = "@bob:b"
BOBBY = "@bobby:a"


class UserDirectoryStoreTestCase(unittest.TestCase):
    @defer.inlineCallbacks
    def setUp(self):
        self.hs = yield setup_test_homeserver(self.addCleanup)
        self.store = UserDirectoryStore(self.hs.get_db_conn(), self.hs)

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
        yield self.store.add_users_to_public_room("!room:id", [ALICE, BOB])
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

    @defer.inlineCallbacks
    def test_cannot_add_support_user_to_directory(self):
        self.hs.config.user_directory_search_all_users = True
        self.hs.config.support_user_id = "@support:test"
        SUPPORT_USER = self.hs.config.support_user_id
        yield self.store.add_profiles_to_user_dir(
            "!room:id",
            {SUPPORT_USER: ProfileInfo(None, "support")},
        )
        yield self.store.add_users_to_public_room("!room:id", [SUPPORT_USER])
        yield self.store.add_users_who_share_room(
            "!room:id", False, ((ALICE, SUPPORT_USER),)
        )

        r = yield self.store.search_user_dir(ALICE, "support", 10)
        self.assertFalse(r["limited"])
        self.assertEqual(0, len(r["results"]))

        # add_users_who_share_room
        # add_users_to_public_room
        # add_profiles_to_user_dir
        # update_user_in_user_dir
        # update_profile_in_user_dir
        # update_user_in_public_user_list

        # yield self.store.add_profiles_to_user_dir(
        #     "!room:id",
        #     {SUPPORT_USER: ProfileInfo(None, "support")},
        # )
        # yield self.store.add_profiles_to_user_dir(SUPPORT_USER,
        #
        #
        #
        # yield self.store.add_users_to_public_room("!room:id", [SUPPORT_USER])
        #
        # yield self.store.add_users_who_share_room(
        #     "!room:id", False, ((ALICE, SUPPORT_USER), (BOB, SUPPORT_USER))
        # )
