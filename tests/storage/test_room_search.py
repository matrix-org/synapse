# Copyright 2021 The Matrix.org Foundation C.I.C.
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

from typing import List, Tuple, Union
from unittest.case import SkipTest
from unittest.mock import PropertyMock, patch

from twisted.test.proto_helpers import MemoryReactor

import synapse.rest.admin
from synapse.api.constants import EventTypes
from synapse.api.errors import StoreError
from synapse.rest.client import login, room
from synapse.server import HomeServer
from synapse.storage.databases.main import DataStore
from synapse.storage.databases.main.search import Phrase, SearchToken, _tokenize_query
from synapse.storage.engines import PostgresEngine
from synapse.storage.engines.sqlite import Sqlite3Engine
from synapse.util import Clock

from tests.unittest import HomeserverTestCase, skip_unless
from tests.utils import USE_POSTGRES_FOR_TESTS


class EventSearchInsertionTest(HomeserverTestCase):
    servlets = [
        synapse.rest.admin.register_servlets_for_client_rest_resource,
        login.register_servlets,
        room.register_servlets,
    ]

    def test_null_byte(self):
        """
        Postgres/SQLite don't like null bytes going into the search tables. Internally
        we replace those with a space.

        Ensure this doesn't break anything.
        """

        # Register a user and create a room, create some messages
        self.register_user("alice", "password")
        access_token = self.login("alice", "password")
        room_id = self.helper.create_room_as("alice", tok=access_token)

        # Send messages and ensure they don't cause an internal server
        # error
        for body in ["hi\u0000bob", "another message", "hi alice"]:
            response = self.helper.send(room_id, body, tok=access_token)
            self.assertIn("event_id", response)

        # Check that search works for the message where the null byte was replaced
        store = self.hs.get_datastores().main
        result = self.get_success(
            store.search_msgs([room_id], "hi bob", ["content.body"])
        )
        self.assertEqual(result.get("count"), 1)
        if isinstance(store.database_engine, PostgresEngine):
            self.assertIn("hi", result.get("highlights"))
            self.assertIn("bob", result.get("highlights"))

        # Check that search works for an unrelated message
        result = self.get_success(
            store.search_msgs([room_id], "another", ["content.body"])
        )
        self.assertEqual(result.get("count"), 1)
        if isinstance(store.database_engine, PostgresEngine):
            self.assertIn("another", result.get("highlights"))

        # Check that search works for a search term that overlaps with the message
        # containing a null byte and an unrelated message.
        result = self.get_success(store.search_msgs([room_id], "hi", ["content.body"]))
        self.assertEqual(result.get("count"), 2)
        result = self.get_success(
            store.search_msgs([room_id], "hi alice", ["content.body"])
        )
        if isinstance(store.database_engine, PostgresEngine):
            self.assertIn("alice", result.get("highlights"))

    def test_non_string(self):
        """Test that non-string `value`s are not inserted into `event_search`.

        This is particularly important when using sqlite, since a sqlite column can hold
        both strings and integers. When using Postgres, integers are automatically
        converted to strings.

        Regression test for #11918.
        """
        store = self.hs.get_datastores().main

        # Register a user and create a room
        user_id = self.register_user("alice", "password")
        access_token = self.login("alice", "password")
        room_id = self.helper.create_room_as("alice", tok=access_token)
        room_version = self.get_success(store.get_room_version(room_id))

        # Construct a message with a numeric body to be received over federation
        # The message can't be sent using the client API, since Synapse's event
        # validation will reject it.
        prev_event_ids = self.get_success(store.get_prev_events_for_room(room_id))
        prev_event = self.get_success(store.get_event(prev_event_ids[0]))
        prev_state_map = self.get_success(
            self.hs.get_storage_controllers().state.get_state_ids_for_event(
                prev_event_ids[0]
            )
        )

        event_dict = {
            "type": EventTypes.Message,
            "content": {"msgtype": "m.text", "body": 2},
            "room_id": room_id,
            "sender": user_id,
            "depth": prev_event.depth + 1,
            "prev_events": prev_event_ids,
            "origin_server_ts": self.clock.time_msec(),
        }
        builder = self.hs.get_event_builder_factory().for_room_version(
            room_version, event_dict
        )
        event = self.get_success(
            builder.build(
                prev_event_ids=prev_event_ids,
                auth_event_ids=self.hs.get_event_auth_handler().compute_auth_events(
                    builder,
                    prev_state_map,
                    for_verification=False,
                ),
                depth=event_dict["depth"],
            )
        )

        # Receive the event
        self.get_success(
            self.hs.get_federation_event_handler().on_receive_pdu(
                self.hs.hostname, event
            )
        )

        # The event should not have an entry in the `event_search` table
        f = self.get_failure(
            store.db_pool.simple_select_one_onecol(
                "event_search",
                {"room_id": room_id, "event_id": event.event_id},
                "event_id",
            ),
            StoreError,
        )
        self.assertEqual(f.value.code, 404)

    @skip_unless(not USE_POSTGRES_FOR_TESTS, "requires sqlite")
    def test_sqlite_non_string_deletion_background_update(self):
        """Test the background update to delete bad rows from `event_search`."""
        store = self.hs.get_datastores().main

        # Populate `event_search` with dummy data
        self.get_success(
            store.db_pool.simple_insert_many(
                "event_search",
                keys=["event_id", "room_id", "key", "value"],
                values=[
                    ("event1", "room_id", "content.body", "hi"),
                    ("event2", "room_id", "content.body", "2"),
                    ("event3", "room_id", "content.body", 3),
                ],
                desc="populate_event_search",
            )
        )

        # Run the background update
        store.db_pool.updates._all_done = False
        self.get_success(
            store.db_pool.simple_insert(
                "background_updates",
                {
                    "update_name": "event_search_sqlite_delete_non_strings",
                    "progress_json": "{}",
                },
            )
        )
        self.wait_for_background_updates()

        # The non-string `value`s ought to be gone now.
        values = self.get_success(
            store.db_pool.simple_select_onecol(
                "event_search",
                {"room_id": "room_id"},
                "value",
            ),
        )
        self.assertCountEqual(values, ["hi", "2"])


class MessageSearchTest(HomeserverTestCase):
    """
    Check message search.

    A powerful way to check the behaviour is to run the following in Postgres >= 11:

        # SELECT websearch_to_tsquery('english', <your string>);

    The result can be compared to the tokenized version for SQLite and Postgres < 11.

    """

    servlets = [
        synapse.rest.admin.register_servlets_for_client_rest_resource,
        login.register_servlets,
        room.register_servlets,
    ]

    PHRASE = "the quick brown fox jumps over the lazy dog"

    # Each entry is a search query, followed by either a boolean of whether it is
    # in the phrase OR a tuple of booleans: whether it matches using websearch
    # and using plain search.
    COMMON_CASES: List[Tuple[str, Union[bool, Tuple[bool, bool]]]] = [
        ("nope", False),
        ("brown", True),
        ("quick brown", True),
        ("brown quick", True),
        ("quick \t brown", True),
        ("jump", True),
        ("brown nope", False),
        ('"brown quick"', (False, True)),
        ('"jumps over"', True),
        ('"quick fox"', (False, True)),
        ("nope OR doublenope", False),
        ("furphy OR fox", (True, False)),
        ("fox -nope", (True, False)),
        ("fox -brown", (False, True)),
        ('"fox" quick', True),
        ('"quick brown', True),
        ('" quick "', True),
        ('" nope"', False),
    ]
    # TODO Test non-ASCII cases.

    # Case that fail on SQLite.
    POSTGRES_CASES: List[Tuple[str, Union[bool, Tuple[bool, bool]]]] = [
        # SQLite treats NOT as a binary operator.
        ("- fox", (False, True)),
        ("- nope", (True, False)),
        ('"-fox quick', (False, True)),
        # PostgreSQL skips stop words.
        ('"the quick brown"', True),
        ('"over lazy"', True),
    ]

    def prepare(
        self, reactor: MemoryReactor, clock: Clock, homeserver: HomeServer
    ) -> None:
        # Register a user and create a room, create some messages
        self.register_user("alice", "password")
        self.access_token = self.login("alice", "password")
        self.room_id = self.helper.create_room_as("alice", tok=self.access_token)

        # Send the phrase as a message and check it was created
        response = self.helper.send(self.room_id, self.PHRASE, tok=self.access_token)
        self.assertIn("event_id", response)

        # The behaviour of a missing trailing double quote changed in PostgreSQL 14
        # from ignoring the initial double quote to treating it as a phrase.
        main_store = homeserver.get_datastores().main
        found = False
        if isinstance(main_store.database_engine, PostgresEngine):
            assert main_store.database_engine._version is not None
            found = main_store.database_engine._version < 140000
        self.COMMON_CASES.append(('"fox quick', (found, True)))

    def test_tokenize_query(self) -> None:
        """Test the custom logic to tokenize a user's query."""
        cases = (
            ("brown", ["brown"]),
            ("quick brown", ["quick", SearchToken.And, "brown"]),
            ("quick \t brown", ["quick", SearchToken.And, "brown"]),
            ('"brown quick"', [Phrase(["brown", "quick"])]),
            ("furphy OR fox", ["furphy", SearchToken.Or, "fox"]),
            ("fox -brown", ["fox", SearchToken.Not, "brown"]),
            ("- fox", [SearchToken.Not, "fox"]),
            ('"fox" quick', [Phrase(["fox"]), SearchToken.And, "quick"]),
            # No trailing double quote.
            ('"fox quick', [Phrase(["fox", "quick"])]),
            ('"-fox quick', [Phrase(["-fox", "quick"])]),
            ('" quick "', [Phrase(["quick"])]),
            (
                'q"uick brow"n',
                [
                    "q",
                    SearchToken.And,
                    Phrase(["uick", "brow"]),
                    SearchToken.And,
                    "n",
                ],
            ),
            (
                '-"quick brown"',
                [SearchToken.Not, Phrase(["quick", "brown"])],
            ),
        )

        for query, expected in cases:
            tokenized = _tokenize_query(query)
            self.assertEqual(
                tokenized, expected, f"{tokenized} != {expected} for {query}"
            )

    def _check_test_cases(
        self,
        store: DataStore,
        cases: List[Tuple[str, Union[bool, Tuple[bool, bool]]]],
        index=0,
    ) -> None:
        # Run all the test cases versus search_msgs
        for query, expect_to_contain in cases:
            if isinstance(expect_to_contain, tuple):
                expect_to_contain = expect_to_contain[index]

            result = self.get_success(
                store.search_msgs([self.room_id], query, ["content.body"])
            )
            self.assertEquals(
                result["count"],
                1 if expect_to_contain else 0,
                f"expected '{query}' to match '{self.PHRASE}'"
                if expect_to_contain
                else f"'{query}' unexpectedly matched '{self.PHRASE}'",
            )
            self.assertEquals(
                len(result["results"]),
                1 if expect_to_contain else 0,
                "results array length should match count",
            )

        # Run them again versus search_rooms
        for query, expect_to_contain in cases:
            if isinstance(expect_to_contain, tuple):
                expect_to_contain = expect_to_contain[index]

            result = self.get_success(
                store.search_rooms([self.room_id], query, ["content.body"], 10)
            )
            self.assertEquals(
                result["count"],
                1 if expect_to_contain else 0,
                f"expected '{query}' to match '{self.PHRASE}'"
                if expect_to_contain
                else f"'{query}' unexpectedly matched '{self.PHRASE}'",
            )
            self.assertEquals(
                len(result["results"]),
                1 if expect_to_contain else 0,
                "results array length should match count",
            )

    def test_postgres_web_search_for_phrase(self):
        """
        Test searching for phrases using typical web search syntax, as per postgres' websearch_to_tsquery.
        This test is skipped unless the postgres instance supports websearch_to_tsquery.
        """

        store = self.hs.get_datastores().main
        if not isinstance(store.database_engine, PostgresEngine):
            raise SkipTest("Test only applies when postgres is used as the database")

        if store.database_engine.tsquery_func != "websearch_to_tsquery":
            raise SkipTest(
                "Test only applies when postgres supporting websearch_to_tsquery is used as the database"
            )

        self._check_test_cases(store, self.COMMON_CASES + self.POSTGRES_CASES, index=0)

    def test_postgres_non_web_search_for_phrase(self):
        """
        Test postgres searching for phrases without using web search, which is used when websearch_to_tsquery isn't
        supported by the current postgres version.
        """

        store = self.hs.get_datastores().main
        if not isinstance(store.database_engine, PostgresEngine):
            raise SkipTest("Test only applies when postgres is used as the database")

        # Patch supports_websearch_to_tsquery to always return False to ensure we're testing the plainto_tsquery path.
        with patch(
            "synapse.storage.engines.postgres.PostgresEngine.tsquery_func",
            new_callable=PropertyMock,
        ) as supports_websearch_to_tsquery:
            supports_websearch_to_tsquery.return_value = "plainto_tsquery"
            self._check_test_cases(
                store, self.COMMON_CASES + self.POSTGRES_CASES, index=1
            )

    def test_sqlite_search(self):
        """
        Test sqlite searching for phrases.
        """
        store = self.hs.get_datastores().main
        if not isinstance(store.database_engine, Sqlite3Engine):
            raise SkipTest("Test only applies when sqlite is used as the database")

        self._check_test_cases(store, self.COMMON_CASES, index=0)
