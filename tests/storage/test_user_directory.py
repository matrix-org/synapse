# Copyright 2018-2021 The Matrix.org Foundation C.I.C.
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
from typing import Dict, List, Tuple

from synapse.storage import DataStore

from tests.unittest import HomeserverTestCase, override_config

ALICE = "@alice:a"
BOB = "@bob:b"
BOBBY = "@bobby:a"
# The localpart isn't 'Bela' on purpose so we can test looking up display names.
BELA = "@somenickname:a"


class GetUserDirectoryTables:
    """Helper functions that we want to reuse in tests/handlers/test+user_directory.py"""

    def __init__(self, store: DataStore):
        self.store = store

    def _compress_shared(self, shared: List[Dict[str, str]]):
        """
        Compress a list of users who share rooms dicts to a list of tuples.
        """
        r = set()
        for i in shared:
            r.add((i["user_id"], i["other_user_id"], i["room_id"]))
        return r

    async def get_users_in_public_rooms(self) -> List[Tuple[str, str]]:
        r = await self.store.db_pool.simple_select_list(
            "users_in_public_rooms", None, ("user_id", "room_id")
        )

        retval = []
        for i in r:
            retval.append((i["user_id"], i["room_id"]))
        return retval

    async def get_users_who_share_private_rooms(self) -> List[Dict[str, str]]:
        return await self.store.db_pool.simple_select_list(
            "users_who_share_private_rooms",
            None,
            ["user_id", "other_user_id", "room_id"],
        )


class UserDirectoryStoreTestCase(HomeserverTestCase):
    def prepare(self, reactor, clock, hs):
        self.store = hs.get_datastore()

        # alice and bob are both in !room_id. bobby is not but shares
        # a homeserver with alice.
        self.get_success(self.store.update_profile_in_user_dir(ALICE, "alice", None))
        self.get_success(self.store.update_profile_in_user_dir(BOB, "bob", None))
        self.get_success(self.store.update_profile_in_user_dir(BOBBY, "bobby", None))
        self.get_success(self.store.update_profile_in_user_dir(BELA, "Bela", None))
        self.get_success(self.store.add_users_in_public_rooms("!room:id", (ALICE, BOB)))

    def test_search_user_dir(self):
        # normally when alice searches the directory she should just find
        # bob because bobby doesn't share a room with her.
        r = self.get_success(self.store.search_user_dir(ALICE, "bob", 10))
        self.assertFalse(r["limited"])
        self.assertEqual(1, len(r["results"]))
        self.assertDictEqual(
            r["results"][0], {"user_id": BOB, "display_name": "bob", "avatar_url": None}
        )

    @override_config({"user_directory": {"search_all_users": True}})
    def test_search_user_dir_all_users(self):
        r = self.get_success(self.store.search_user_dir(ALICE, "bob", 10))
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

    @override_config({"user_directory": {"search_all_users": True}})
    def test_search_user_dir_stop_words(self):
        """Tests that a user can look up another user by searching for the start if its
        display name even if that name happens to be a common English word that would
        usually be ignored in full text searches.
        """
        r = self.get_success(self.store.search_user_dir(ALICE, "be", 10))
        self.assertFalse(r["limited"])
        self.assertEqual(1, len(r["results"]))
        self.assertDictEqual(
            r["results"][0],
            {"user_id": BELA, "display_name": "Bela", "avatar_url": None},
        )
