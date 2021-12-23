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

from typing import Tuple
from unittest.case import SkipTest
from unittest.mock import PropertyMock, patch

import synapse.rest.admin
from synapse.rest.client import login, room
from synapse.storage.databases.main import DataStore
from synapse.storage.engines import PostgresEngine
from synapse.storage.engines.sqlite import Sqlite3Engine

from tests.unittest import HomeserverTestCase


class NullByteInsertionTest(HomeserverTestCase):
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
        store = self.hs.get_datastore()
        result = self.get_success(
            store.search_msgs([room_id], "hi bob", ["content.body"])
        )
        self.assertEquals(result.get("count"), 1)
        if isinstance(store.database_engine, PostgresEngine):
            self.assertIn("hi", result.get("highlights"))
            self.assertIn("bob", result.get("highlights"))

        # Check that search works for an unrelated message
        result = self.get_success(
            store.search_msgs([room_id], "another", ["content.body"])
        )
        self.assertEquals(result.get("count"), 1)
        if isinstance(store.database_engine, PostgresEngine):
            self.assertIn("another", result.get("highlights"))

        # Check that search works for a search term that overlaps with the message
        # containing a null byte and an unrelated message.
        result = self.get_success(store.search_msgs([room_id], "hi", ["content.body"]))
        self.assertEquals(result.get("count"), 2)
        result = self.get_success(
            store.search_msgs([room_id], "hi alice", ["content.body"])
        )
        if isinstance(store.database_engine, PostgresEngine):
            self.assertIn("alice", result.get("highlights"))


class MessageSearchTest(HomeserverTestCase):
    servlets = [
        synapse.rest.admin.register_servlets_for_client_rest_resource,
        login.register_servlets,
        room.register_servlets,
    ]

    PHRASE = "the quick brown fox jumps over the lazy dog"

    def setUp(self):            
        super().setUp()

        # Register a user and create a room, create some messages
        self.register_user("alice", "password")
        self.access_token = self.login("alice", "password")
        self.room_id = self.helper.create_room_as("alice", tok=self.access_token)

        # Send the phrase as a message and check it was created
        response = self.helper.send(self.room_id, self.PHRASE, tok=self.access_token)
        self.assertIn("event_id", response)

    def _check_test_cases(self, store: DataStore, cases: list[Tuple[str, bool]]) -> None:
        # Run all the test cases versus search_msgs
        for query, has_results in cases:
            result = self.get_success(
                store.search_msgs([self.room_id], query, ["content.body"])
            )
            self.assertEquals(result["count"], 1 if has_results else 0, query)
            self.assertEquals(len(result["results"]), 1 if has_results else 0, query)

        # Run them again versus search_rooms
        for query, has_results in cases:
            result = self.get_success(
                store.search_rooms([self.room_id], query, ["content.body"], 10)
            )
            self.assertEquals(result["count"], 1 if has_results else 0, query)
            self.assertEquals(len(result["results"]), 1 if has_results else 0, query)

    def test_postgres_web_search_for_phrase(self):
        """
        Test searching for phrases using typical web search syntax, as per postgres' websearch_to_tsquery.
        This test is skipped unless the postgres instance supports websearch_to_tsquery.
        """

        store = self.hs.get_datastore()
        if not isinstance(store.database_engine, PostgresEngine):
            raise SkipTest("Test only applies when postgres is used as the database")

        if not store.database_engine.supports_websearch_to_tsquery:
            raise SkipTest(
                "Test only applies when postgres supporting websearch_to_tsquery is used as the database"
            )

        cases = [
            ("brown", True),
            ("quick brown", True),
            ("brown quick", True),
            ('"brown quick"', False),
            ('"jumps over"', True),
            ('"quick fox"', False),
            ("furphy OR fox", True),
            ("nope OR doublenope", False),
            ("-fox", False),
            ("-nope", True),
        ]

        self._check_test_cases(store, cases)

    def test_postgres_non_web_search_for_phrase(self):
        """
        Test postgres searching for phrases without using web search, which is used when websearch_to_tsquery isn't
        supported by the current postgres version.
        """

        store = self.hs.get_datastore()
        if not isinstance(store.database_engine, PostgresEngine):
            raise SkipTest("Test only applies when postgres is used as the database")

        cases = [
            ("nope", False),
            ("brown", True),
            ("quick brown", True),
            ("brown quick", True),
            ("brown nope", False),
            ("furphy OR fox", False),  # syntax not supported, OR will be ignored as it'll be between &
            ('"jumps over"', True),  # syntax not supported, we strip quotes
            ("-nope", False),  # syntax not supported, - will be ignored
        ]

        # Patch supports_websearch_to_tsquery to always return False to ensure we're testing the plainto_tsquery path.
        with patch(
            "synapse.storage.engines.postgres.PostgresEngine.supports_websearch_to_tsquery",
            new_callable=PropertyMock,
        ) as supports_websearch_to_tsquery:
            supports_websearch_to_tsquery.return_value = False
            self._check_test_cases(store, cases)            

    def test_sqlite_search(self):
        """
        Test sqlite searching for phrases.
        """
        store = self.hs.get_datastore()
        if not isinstance(store.database_engine, Sqlite3Engine):
            raise SkipTest("Test only applies when sqlite is used as the database")

        cases = [
            ("nope", False),
            ("brown", True),
            ("quick brown", True),
            ("brown quick", True),
            ("brown nope", False),
            ("furphy OR fox", True),  # sqllite supports OR
            ('"jumps over"', True),              
            ('"quick fox"', False), # syntax supports quotes
            ("fox NOT nope", True),  # sqllite supports NOT
        ]

        self._check_test_cases(store, cases)
