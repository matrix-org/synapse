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
from typing import List, Tuple, Dict
from unittest.mock import Mock, patch

from synapse.api.constants import UserTypes
from synapse.appservice import ApplicationService
from synapse.rest import admin
from synapse.rest.client import room, login
from synapse.storage import DataStore
from synapse.types import UserID, create_requester
from tests.test_utils.event_injection import inject_member_event
from tests.unittest import HomeserverTestCase, override_config


class GetUserDirectoryTables(HomeserverTestCase):
    """These helpers aren't present on the store itself. We want to use them
    here and in the handler's tests too.
    """

    store: DataStore

    def get_users_in_public_rooms(self) -> List[Tuple[str, str]]:
        r = self.get_success(
            self.store.db_pool.simple_select_list(
                "users_in_public_rooms", None, ("user_id", "room_id")
            )
        )
        retval = []
        for i in r:
            retval.append((i["user_id"], i["room_id"]))
        return retval

    def get_users_who_share_private_rooms(self) -> List[Tuple[str, str, str]]:
        return self.get_success(
            self.store.db_pool.simple_select_list(
                "users_who_share_private_rooms",
                None,
                ["user_id", "other_user_id", "room_id"],
            )
        )

    def get_users_in_user_directory(self) -> Dict[str, str]:
        # Just the set of usernames for now
        r = self.get_success(
            self.store.db_pool.simple_select_list(
                "user_directory", None, ("user_id", "display_name")
            )
        )
        return {entry["user_id"]: entry["display_name"] for entry in r}

    def _compress_shared(self, shared):
        """
        Compress a list of users who share rooms dicts to a list of tuples.
        """
        r = set()
        for i in shared:
            r.add((i["user_id"], i["other_user_id"], i["room_id"]))
        return r


class UserDirectoryInitialPopulationTestcase(
    GetUserDirectoryTables, HomeserverTestCase
):
    """Ensure that the initial background process creates the user directory data
    as intended.

    See also tests/handlers/test_user_directory.py for similar checks. They
    test the incremental updates, rather than the big batch of updates.
    """

    servlets = [
        login.register_servlets,
        admin.register_servlets_for_client_rest_resource,
        room.register_servlets,
    ]

    def prepare(self, reactor, clock, hs):
        self.store = hs.get_datastore()

    def _purge_and_rebuild_user_dir(self):
        """Nuke the user directory tables, start the background process to
        repopulate them, and wait for the process to complete. This allows us
        to inspect the outcome of the background process alone, without any of
        the other incremental updates.
        """
        self.get_success(self.store.update_user_directory_stream_pos(None))
        self.get_success(self.store.delete_all_from_user_dir())

        shares_private = self.get_users_who_share_private_rooms()
        public_users = self.get_users_in_public_rooms()

        # Nothing updated yet
        self.assertEqual(shares_private, [])
        self.assertEqual(public_users, [])

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

        while not self.get_success(
            self.store.db_pool.updates.has_completed_background_updates()
        ):
            self.get_success(
                self.store.db_pool.updates.do_next_background_update(100), by=0.1
            )

    def test_populates_local_users(self):
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

        self._purge_and_rebuild_user_dir()

        shares_private = self.get_users_who_share_private_rooms()
        public_users = self.get_users_in_public_rooms()

        # User 1 and User 2 are in the same public room
        self.assertEqual(set(public_users), {(u1, room), (u2, room)})

        # User 1 and User 3 share private rooms
        self.assertEqual(
            self._compress_shared(shares_private),
            {(u1, u3, private_room), (u3, u1, private_room)},
        )

        # All three should have entries in the directory
        self.assertEqual(set(self.get_users_in_user_directory().keys()), {u1, u2, u3})

    def test_population_excludes_support_user(self):
        support = "@support1:test"
        self.get_success(
            self.store.register_user(
                user_id=support, password_hash=None, user_type=UserTypes.SUPPORT
            )
        )

        self._purge_and_rebuild_user_dir()
        # TODO add support user to a public and private room. Check that
        # users_in_public_rooms and users_who_share_private_rooms is empty.
        self.assertEqual(self.get_users_in_user_directory(), {})

    def test_population_excludes_appservice_user(self):
        as_token = "i_am_an_app_service"
        appservice = ApplicationService(
            as_token,
            self.hs.config.server_name,
            id="1234",
            namespaces={"users": [{"regex": r"@as_user.*", "exclusive": True}]},
            sender="@as:test",
        )
        self.store.services_cache.append(appservice)

        as_user = "@as_user_potato:test"
        self.get_success(self.store.register_user(user_id=as_user, password_hash=None))

        # TODO can we configure the app service up front somehow? This is a hack.
        mock_regex = Mock()
        mock_regex.match = lambda user_id: user_id == as_user
        with patch.object(self.store, "exclusive_user_regex", mock_regex):
            self._purge_and_rebuild_user_dir()

        # TODO add AS user to a public and private room. Check that
        # users_in_public_rooms and users_who_share_private_rooms is empty.
        self.assertEqual(self.get_users_in_user_directory(), {})

    def test_population_excludes_deactivated_user(self):
        user = self.register_user("rip", "pass")
        user_token = self.login(user, "pass")
        self.helper.create_room_as(user, is_public=True, tok=user_token)
        self.helper.create_room_as(user, is_public=False, tok=user_token)
        self.get_success(self.store.set_user_deactivated_status(user, True))

        self._purge_and_rebuild_user_dir()

        self.assertEqual(self.get_users_in_public_rooms(), [])
        self.assertEqual(self.get_users_who_share_private_rooms(), [])
        self.assertEqual(self.get_users_in_user_directory(), {})
ALICE = "@alice:a"
BOB = "@bob:b"
BOBBY = "@bobby:a"
# The localpart isn't 'Bela' on purpose so we can test looking up display names.
BELA = "@somenickname:a"


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
