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
import re
from typing import Any, Dict, List, Optional, Set, Tuple, cast
from unittest import mock
from unittest.mock import Mock, patch

from twisted.test.proto_helpers import MemoryReactor

from synapse.api.constants import EventTypes, Membership, UserTypes
from synapse.appservice import ApplicationService
from synapse.rest import admin
from synapse.rest.client import login, register, room
from synapse.server import HomeServer
from synapse.storage import DataStore
from synapse.storage.background_updates import _BackgroundUpdateHandler
from synapse.storage.databases.main import user_directory
from synapse.storage.databases.main.user_directory import (
    _parse_words_with_icu,
    _parse_words_with_regex,
)
from synapse.storage.roommember import ProfileInfo
from synapse.util import Clock

from tests.server import ThreadedMemoryReactorClock
from tests.test_utils.event_injection import inject_member_event
from tests.unittest import HomeserverTestCase, override_config

try:
    import icu
except ImportError:
    icu = None  # type: ignore


ALICE = "@alice:a"
BOB = "@bob:b"
BOBBY = "@bobby:a"
# The localpart isn't 'Bela' on purpose so we can test looking up display names.
BELA = "@somenickname:example.org"


class GetUserDirectoryTables:
    """Helper functions that we want to reuse in tests/handlers/test_user_directory.py"""

    def __init__(self, store: DataStore):
        self.store = store

    async def get_users_in_public_rooms(self) -> Set[Tuple[str, str]]:
        """Fetch the entire `users_in_public_rooms` table.

        Returns a list of tuples (user_id, room_id) where room_id is public and
        contains the user with the given id.
        """
        r = cast(
            List[Tuple[str, str]],
            await self.store.db_pool.simple_select_list(
                "users_in_public_rooms", None, ("user_id", "room_id")
            ),
        )
        return set(r)

    async def get_users_who_share_private_rooms(self) -> Set[Tuple[str, str, str]]:
        """Fetch the entire `users_who_share_private_rooms` table.

        Returns a set of tuples (user_id, other_user_id, room_id) corresponding
        to the rows of `users_who_share_private_rooms`.
        """

        rows = cast(
            List[Tuple[str, str, str]],
            await self.store.db_pool.simple_select_list(
                "users_who_share_private_rooms",
                None,
                ["user_id", "other_user_id", "room_id"],
            ),
        )
        return set(rows)

    async def get_users_in_user_directory(self) -> Set[str]:
        """Fetch the set of users in the `user_directory` table.

        This is useful when checking we've correctly excluded users from the directory.
        """
        result = cast(
            List[Tuple[str]],
            await self.store.db_pool.simple_select_list(
                "user_directory",
                None,
                ["user_id"],
            ),
        )
        return {row[0] for row in result}

    async def get_profiles_in_user_directory(self) -> Dict[str, ProfileInfo]:
        """Fetch users and their profiles from the `user_directory` table.

        This is useful when we want to inspect display names and avatars.
        It's almost the entire contents of the `user_directory` table: the only
        thing missing is an unused room_id column.
        """
        rows = cast(
            List[Tuple[str, Optional[str], Optional[str]]],
            await self.store.db_pool.simple_select_list(
                "user_directory",
                None,
                ("user_id", "display_name", "avatar_url"),
            ),
        )
        return {
            user_id: ProfileInfo(display_name=display_name, avatar_url=avatar_url)
            for user_id, display_name, avatar_url in rows
        }

    async def get_tables(
        self,
    ) -> Tuple[Set[str], Set[Tuple[str, str]], Set[Tuple[str, str, str]]]:
        """Multiple tests want to inspect these tables, so expose them together."""
        return (
            await self.get_users_in_user_directory(),
            await self.get_users_in_public_rooms(),
            await self.get_users_who_share_private_rooms(),
        )


class UserDirectoryInitialPopulationTestcase(HomeserverTestCase):
    """Ensure that rebuilding the directory writes the correct data to the DB.

    See also tests/handlers/test_user_directory.py for similar checks. They
    test the incremental updates, rather than the big rebuild.
    """

    servlets = [
        login.register_servlets,
        admin.register_servlets,
        room.register_servlets,
        register.register_servlets,
    ]

    def make_homeserver(
        self, reactor: ThreadedMemoryReactorClock, clock: Clock
    ) -> HomeServer:
        self.appservice = ApplicationService(
            token="i_am_an_app_service",
            id="1234",
            namespaces={"users": [{"regex": r"@as_user.*", "exclusive": True}]},
            sender="@as:test",
        )

        mock_load_appservices = Mock(return_value=[self.appservice])
        with patch(
            "synapse.storage.databases.main.appservice.load_appservices",
            mock_load_appservices,
        ):
            hs = super().make_homeserver(reactor, clock)
        return hs

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self.store = hs.get_datastores().main
        self.user_dir_helper = GetUserDirectoryTables(self.store)

    def _purge_and_rebuild_user_dir(self) -> None:
        """Nuke the user directory tables, start the background process to
        repopulate them, and wait for the process to complete. This allows us
        to inspect the outcome of the background process alone, without any of
        the other incremental updates.
        """
        self.get_success(self.store.update_user_directory_stream_pos(None))
        self.get_success(self.store.delete_all_from_user_dir())

        shares_private = self.get_success(
            self.user_dir_helper.get_users_who_share_private_rooms()
        )
        public_users = self.get_success(
            self.user_dir_helper.get_users_in_public_rooms()
        )

        # Nothing updated yet
        self.assertEqual(shares_private, set())
        self.assertEqual(public_users, set())

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

        self.wait_for_background_updates()

    def test_initial(self) -> None:
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

        # Do the initial population of the user directory via the background update
        self._purge_and_rebuild_user_dir()

        users, in_public, in_private = self.get_success(
            self.user_dir_helper.get_tables()
        )

        # User 1 and User 2 are in the same public room
        self.assertEqual(in_public, {(u1, room), (u2, room)})
        # User 1 and User 3 share private rooms
        self.assertEqual(in_private, {(u1, u3, private_room), (u3, u1, private_room)})
        # All three should have entries in the directory
        self.assertEqual(users, {u1, u2, u3})

    # The next four tests (test_population_excludes_*) all set up
    #   - A normal user included in the user dir
    #   - A public and private room created by that user
    #   - A user excluded from the room dir, belonging to both rooms

    # They match similar logic in handlers/test_user_directory.py But that tests
    # updating the directory; this tests rebuilding it from scratch.

    def _create_rooms_and_inject_memberships(
        self, creator: str, token: str, joiner: str
    ) -> Tuple[str, str]:
        """Create a public and private room as a normal user.
        Then get the `joiner` into those rooms.
        """
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

    def _check_room_sharing_tables(
        self, normal_user: str, public_room: str, private_room: str
    ) -> None:
        # After rebuilding the directory, we should only see the normal user.
        users, in_public, in_private = self.get_success(
            self.user_dir_helper.get_tables()
        )
        self.assertEqual(users, {normal_user})
        self.assertEqual(in_public, {(normal_user, public_room)})
        self.assertEqual(in_private, set())

    def test_population_excludes_support_user(self) -> None:
        # Create a normal and support user.
        user = self.register_user("user", "pass")
        token = self.login(user, "pass")
        support = "@support1:test"
        self.get_success(
            self.store.register_user(
                user_id=support, password_hash=None, user_type=UserTypes.SUPPORT
            )
        )

        # Join the support user to rooms owned by the normal user.
        public, private = self._create_rooms_and_inject_memberships(
            user, token, support
        )

        # Rebuild the directory.
        self._purge_and_rebuild_user_dir()

        # Check the support user is not in the directory.
        self._check_room_sharing_tables(user, public, private)

    def test_population_excludes_deactivated_user(self) -> None:
        user = self.register_user("naughty", "pass")
        admin = self.register_user("admin", "pass", admin=True)
        admin_token = self.login(admin, "pass")

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

        # Rebuild the user dir. The deactivated user should be missing.
        self._purge_and_rebuild_user_dir()
        self._check_room_sharing_tables(admin, public, private)

    def test_population_excludes_appservice_user(self) -> None:
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

        # Rebuild the directory.
        self._purge_and_rebuild_user_dir()

        # Check the AS user is not in the directory.
        self._check_room_sharing_tables(user, public, private)

    def test_population_excludes_appservice_sender(self) -> None:
        user = self.register_user("user", "pass")
        token = self.login(user, "pass")

        # Join the AS sender to rooms owned by the normal user.
        public, private = self._create_rooms_and_inject_memberships(
            user, token, self.appservice.sender
        )

        # Rebuild the directory.
        self._purge_and_rebuild_user_dir()

        # Check the AS sender is not in the directory.
        self._check_room_sharing_tables(user, public, private)

    def test_population_conceals_private_nickname(self) -> None:
        # Make a private room, and set a nickname within
        user = self.register_user("aaaa", "pass")
        user_token = self.login(user, "pass")
        private_room = self.helper.create_room_as(user, is_public=False, tok=user_token)
        self.helper.send_state(
            private_room,
            EventTypes.Member,
            state_key=user,
            body={"membership": Membership.JOIN, "displayname": "BBBB"},
            tok=user_token,
        )

        # Rebuild the user directory. Make the rescan of the `users` table a no-op
        # so we only see the effect of scanning the `room_memberships` table.
        async def mocked_process_users(*args: Any, **kwargs: Any) -> int:
            await self.store.db_pool.updates._end_background_update(
                "populate_user_directory_process_users"
            )
            return 1

        with mock.patch.dict(
            self.store.db_pool.updates._background_update_handlers,
            populate_user_directory_process_users=_BackgroundUpdateHandler(
                mocked_process_users,
            ),
        ):
            self._purge_and_rebuild_user_dir()

        # Local users are ignored by the scan over rooms
        users = self.get_success(self.user_dir_helper.get_profiles_in_user_directory())
        self.assertEqual(users, {})

        # Do a full rebuild including the scan over the `users` table. The local
        # user should appear with their profile name.
        self._purge_and_rebuild_user_dir()
        users = self.get_success(self.user_dir_helper.get_profiles_in_user_directory())
        self.assertEqual(
            users, {user: ProfileInfo(display_name="aaaa", avatar_url=None)}
        )


class UserDirectoryStoreTestCase(HomeserverTestCase):
    use_icu = False

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self.store = hs.get_datastores().main

        # alice and bob are both in !room_id. bobby is not but shares
        # a homeserver with alice.
        self.get_success(self.store.update_profile_in_user_dir(ALICE, "alice", None))
        self.get_success(self.store.update_profile_in_user_dir(BOB, "bob", None))
        self.get_success(self.store.update_profile_in_user_dir(BOBBY, "bobby", None))
        self.get_success(self.store.update_profile_in_user_dir(BELA, "Bela", None))
        self.get_success(self.store.add_users_in_public_rooms("!room:id", (ALICE, BOB)))

        self._restore_use_icu = user_directory.USE_ICU
        user_directory.USE_ICU = self.use_icu

    def tearDown(self) -> None:
        user_directory.USE_ICU = self._restore_use_icu

    def test_search_user_dir(self) -> None:
        # normally when alice searches the directory she should just find
        # bob because bobby doesn't share a room with her.
        r = self.get_success(self.store.search_user_dir(ALICE, "bob", 10))
        self.assertFalse(r["limited"])
        self.assertEqual(1, len(r["results"]))
        self.assertDictEqual(
            r["results"][0], {"user_id": BOB, "display_name": "bob", "avatar_url": None}
        )

    @override_config({"user_directory": {"search_all_users": True}})
    def test_search_user_dir_all_users(self) -> None:
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
    def test_search_user_limit_correct(self) -> None:
        r = self.get_success(self.store.search_user_dir(ALICE, "bob", 1))
        self.assertTrue(r["limited"])
        self.assertEqual(1, len(r["results"]))

    @override_config({"user_directory": {"search_all_users": True}})
    def test_search_user_dir_stop_words(self) -> None:
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

    @override_config({"user_directory": {"search_all_users": True}})
    def test_search_user_dir_start_of_user_id(self) -> None:
        """Tests that a user can look up another user by searching for the start
        of their user ID.
        """
        r = self.get_success(self.store.search_user_dir(ALICE, "somenickname:exa", 10))
        self.assertFalse(r["limited"])
        self.assertEqual(1, len(r["results"]))
        self.assertDictEqual(
            r["results"][0],
            {"user_id": BELA, "display_name": "Bela", "avatar_url": None},
        )

    @override_config({"user_directory": {"search_all_users": True}})
    def test_search_user_dir_ascii_case_insensitivity(self) -> None:
        """Tests that a user can look up another user by searching for their name in a
        different case.
        """
        CHARLIE = "@someuser:example.org"
        self.get_success(
            self.store.update_profile_in_user_dir(CHARLIE, "Charlie", None)
        )

        r = self.get_success(self.store.search_user_dir(ALICE, "cHARLIE", 10))
        self.assertFalse(r["limited"])
        self.assertEqual(1, len(r["results"]))
        self.assertDictEqual(
            r["results"][0],
            {"user_id": CHARLIE, "display_name": "Charlie", "avatar_url": None},
        )

    @override_config({"user_directory": {"search_all_users": True}})
    def test_search_user_dir_unicode_case_insensitivity(self) -> None:
        """Tests that a user can look up another user by searching for their name in a
        different case.
        """
        IVAN = "@someuser:example.org"
        self.get_success(self.store.update_profile_in_user_dir(IVAN, "Иван", None))

        r = self.get_success(self.store.search_user_dir(ALICE, "иВАН", 10))
        self.assertFalse(r["limited"])
        self.assertEqual(1, len(r["results"]))
        self.assertDictEqual(
            r["results"][0],
            {"user_id": IVAN, "display_name": "Иван", "avatar_url": None},
        )

    @override_config({"user_directory": {"search_all_users": True}})
    def test_search_user_dir_dotted_dotless_i_case_insensitivity(self) -> None:
        """Tests that a user can look up another user by searching for their name in a
        different case, when their name contains dotted or dotless "i"s.

        Some languages have dotted and dotless versions of "i", which are considered to
        be different letters: i <-> İ, ı <-> I. To make things difficult, they reuse the
        ASCII "i" and "I" code points, despite having different lowercase / uppercase
        forms.
        """
        USER = "@someuser:example.org"

        expected_matches = [
            # (search_term, display_name)
            # A search for "i" should match "İ".
            ("iiiii", "İİİİİ"),
            # A search for "I" should match "ı".
            ("IIIII", "ııııı"),
            # A search for "ı" should match "I".
            ("ııııı", "IIIII"),
            # A search for "İ" should match "i".
            ("İİİİİ", "iiiii"),
        ]

        for search_term, display_name in expected_matches:
            self.get_success(
                self.store.update_profile_in_user_dir(USER, display_name, None)
            )

            r = self.get_success(self.store.search_user_dir(ALICE, search_term, 10))
            self.assertFalse(r["limited"])
            self.assertEqual(
                1,
                len(r["results"]),
                f"searching for {search_term!r} did not match {display_name!r}",
            )
            self.assertDictEqual(
                r["results"][0],
                {"user_id": USER, "display_name": display_name, "avatar_url": None},
            )

        # We don't test for negative matches, to allow implementations that consider all
        # the i variants to be the same.

    test_search_user_dir_dotted_dotless_i_case_insensitivity.skip = "not supported"  # type: ignore

    @override_config({"user_directory": {"search_all_users": True}})
    def test_search_user_dir_unicode_normalization(self) -> None:
        """Tests that a user can look up another user by searching for their name with
        either composed or decomposed accents.
        """
        AMELIE = "@someuser:example.org"

        expected_matches = [
            # (search_term, display_name)
            ("Ame\u0301lie", "Amélie"),
            ("Amélie", "Ame\u0301lie"),
        ]

        for search_term, display_name in expected_matches:
            self.get_success(
                self.store.update_profile_in_user_dir(AMELIE, display_name, None)
            )

            r = self.get_success(self.store.search_user_dir(ALICE, search_term, 10))
            self.assertFalse(r["limited"])
            self.assertEqual(
                1,
                len(r["results"]),
                f"searching for {search_term!r} did not match {display_name!r}",
            )
            self.assertDictEqual(
                r["results"][0],
                {"user_id": AMELIE, "display_name": display_name, "avatar_url": None},
            )

    @override_config({"user_directory": {"search_all_users": True}})
    def test_search_user_dir_accent_insensitivity(self) -> None:
        """Tests that a user can look up another user by searching for their name
        without any accents.
        """
        AMELIE = "@someuser:example.org"
        self.get_success(self.store.update_profile_in_user_dir(AMELIE, "Amélie", None))

        r = self.get_success(self.store.search_user_dir(ALICE, "amelie", 10))
        self.assertFalse(r["limited"])
        self.assertEqual(1, len(r["results"]))
        self.assertDictEqual(
            r["results"][0],
            {"user_id": AMELIE, "display_name": "Amélie", "avatar_url": None},
        )

        # It may be desirable for "é"s in search terms to not match plain "e"s and we
        # really don't want "é"s in search terms to match "e"s with different accents.
        # But we don't test for this to allow implementations that consider all
        # "e"-lookalikes to be the same.

    test_search_user_dir_accent_insensitivity.skip = "not supported yet"  # type: ignore


class UserDirectoryStoreTestCaseWithIcu(UserDirectoryStoreTestCase):
    use_icu = True

    if not icu:
        skip = "Requires PyICU"


class UserDirectoryICUTestCase(HomeserverTestCase):
    if not icu:
        skip = "Requires PyICU"

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self.store = hs.get_datastores().main
        self.user_dir_helper = GetUserDirectoryTables(self.store)

    def test_icu_word_boundary(self) -> None:
        """Tests that we correctly detect word boundaries when ICU (International
        Components for Unicode) support is available.
        """

        display_name = "Gáo"

        # This word is not broken down correctly by Python's regular expressions,
        # likely because á is actually a lowercase a followed by a U+0301 combining
        # acute accent. This is specifically something that ICU support fixes.
        matches = re.findall(r"([\w\-]+)", display_name, re.UNICODE)
        self.assertEqual(len(matches), 2)

        self.get_success(
            self.store.update_profile_in_user_dir(ALICE, display_name, None)
        )
        self.get_success(self.store.add_users_in_public_rooms("!room:id", (ALICE,)))

        # Check that searching for this user yields the correct result.
        r = self.get_success(self.store.search_user_dir(BOB, display_name, 10))
        self.assertFalse(r["limited"])
        self.assertEqual(len(r["results"]), 1)
        self.assertDictEqual(
            r["results"][0],
            {"user_id": ALICE, "display_name": display_name, "avatar_url": None},
        )

    def test_icu_word_boundary_punctuation(self) -> None:
        """
        Tests the behaviour of punctuation with the ICU tokeniser.

        Seems to depend on underlying version of ICU.
        """

        # Note: either tokenisation is fine, because Postgres actually splits
        # words itself afterwards.
        self.assertIn(
            _parse_words_with_icu("lazy'fox jumped:over the.dog"),
            (
                # ICU 66 on Ubuntu 20.04
                ["lazy'fox", "jumped", "over", "the", "dog"],
                # ICU 70 on Ubuntu 22.04
                ["lazy'fox", "jumped:over", "the.dog"],
                # pyicu 2.10.2 on Alpine edge / macOS
                ["lazy'fox", "jumped", "over", "the.dog"],
            ),
        )

    def test_regex_word_boundary_punctuation(self) -> None:
        """
        Tests the behaviour of punctuation with the non-ICU tokeniser
        """
        self.assertEqual(
            _parse_words_with_regex("lazy'fox jumped:over the.dog"),
            ["lazy", "fox", "jumped", "over", "the", "dog"],
        )
