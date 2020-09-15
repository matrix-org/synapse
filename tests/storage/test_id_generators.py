# -*- coding: utf-8 -*-
# Copyright 2020 The Matrix.org Foundation C.I.C.
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


from synapse.storage.database import DatabasePool
from synapse.storage.util.id_generators import MultiWriterIdGenerator

from tests.unittest import HomeserverTestCase
from tests.utils import USE_POSTGRES_FOR_TESTS


class MultiWriterIdGeneratorTestCase(HomeserverTestCase):
    if not USE_POSTGRES_FOR_TESTS:
        skip = "Requires Postgres"

    def prepare(self, reactor, clock, hs):
        self.store = hs.get_datastore()
        self.db_pool = self.store.db_pool  # type: DatabasePool

        self.get_success(self.db_pool.runInteraction("_setup_db", self._setup_db))

    def _setup_db(self, txn):
        txn.execute("CREATE SEQUENCE foobar_seq")
        txn.execute(
            """
            CREATE TABLE foobar (
                stream_id BIGINT NOT NULL,
                instance_name TEXT NOT NULL,
                data TEXT
            );
            """
        )

    def _create_id_generator(self, instance_name="master") -> MultiWriterIdGenerator:
        def _create(conn):
            return MultiWriterIdGenerator(
                conn,
                self.db_pool,
                instance_name=instance_name,
                table="foobar",
                instance_column="instance_name",
                id_column="stream_id",
                sequence_name="foobar_seq",
            )

        return self.get_success(self.db_pool.runWithConnection(_create))

    def _insert_rows(self, instance_name: str, number: int):
        """Insert N rows as the given instance, inserting with stream IDs pulled
        from the postgres sequence.
        """

        def _insert(txn):
            for _ in range(number):
                txn.execute(
                    "INSERT INTO foobar VALUES (nextval('foobar_seq'), ?)",
                    (instance_name,),
                )

        self.get_success(self.db_pool.runInteraction("_insert_rows", _insert))

    def _insert_row_with_id(self, instance_name: str, stream_id: int):
        """Insert one row as the given instance with given stream_id, updating
        the postgres sequence position to match.
        """

        def _insert(txn):
            txn.execute(
                "INSERT INTO foobar VALUES (?, ?)", (stream_id, instance_name,),
            )
            txn.execute("SELECT setval('foobar_seq', ?)", (stream_id,))

        self.get_success(self.db_pool.runInteraction("_insert_row_with_id", _insert))

    def test_empty(self):
        """Test an ID generator against an empty database gives sensible
        current positions.
        """

        id_gen = self._create_id_generator()

        # The table is empty so we expect an empty map for positions
        self.assertEqual(id_gen.get_positions(), {})

    def test_single_instance(self):
        """Test that reads and writes from a single process are handled
        correctly.
        """

        # Prefill table with 7 rows written by 'master'
        self._insert_rows("master", 7)

        id_gen = self._create_id_generator()

        self.assertEqual(id_gen.get_positions(), {"master": 7})
        self.assertEqual(id_gen.get_current_token_for_writer("master"), 7)

        # Try allocating a new ID gen and check that we only see position
        # advanced after we leave the context manager.

        async def _get_next_async():
            with await id_gen.get_next() as stream_id:
                self.assertEqual(stream_id, 8)

                self.assertEqual(id_gen.get_positions(), {"master": 7})
                self.assertEqual(id_gen.get_current_token_for_writer("master"), 7)

        self.get_success(_get_next_async())

        self.assertEqual(id_gen.get_positions(), {"master": 8})
        self.assertEqual(id_gen.get_current_token_for_writer("master"), 8)

    def test_multi_instance(self):
        """Test that reads and writes from multiple processes are handled
        correctly.
        """
        self._insert_rows("first", 3)
        self._insert_rows("second", 4)

        first_id_gen = self._create_id_generator("first")
        second_id_gen = self._create_id_generator("second")

        self.assertEqual(first_id_gen.get_positions(), {"first": 3, "second": 7})
        self.assertEqual(first_id_gen.get_current_token_for_writer("first"), 3)
        self.assertEqual(first_id_gen.get_current_token_for_writer("second"), 7)

        # Try allocating a new ID gen and check that we only see position
        # advanced after we leave the context manager.

        async def _get_next_async():
            with await first_id_gen.get_next() as stream_id:
                self.assertEqual(stream_id, 8)

                self.assertEqual(
                    first_id_gen.get_positions(), {"first": 3, "second": 7}
                )

        self.get_success(_get_next_async())

        self.assertEqual(first_id_gen.get_positions(), {"first": 8, "second": 7})

        # However the ID gen on the second instance won't have seen the update
        self.assertEqual(second_id_gen.get_positions(), {"first": 3, "second": 7})

        # ... but calling `get_next` on the second instance should give a unique
        # stream ID

        async def _get_next_async():
            with await second_id_gen.get_next() as stream_id:
                self.assertEqual(stream_id, 9)

                self.assertEqual(
                    second_id_gen.get_positions(), {"first": 3, "second": 7}
                )

        self.get_success(_get_next_async())

        self.assertEqual(second_id_gen.get_positions(), {"first": 3, "second": 9})

        # If the second ID gen gets told about the first, it correctly updates
        second_id_gen.advance("first", 8)
        self.assertEqual(second_id_gen.get_positions(), {"first": 8, "second": 9})

    def test_get_next_txn(self):
        """Test that the `get_next_txn` function works correctly.
        """

        # Prefill table with 7 rows written by 'master'
        self._insert_rows("master", 7)

        id_gen = self._create_id_generator()

        self.assertEqual(id_gen.get_positions(), {"master": 7})
        self.assertEqual(id_gen.get_current_token_for_writer("master"), 7)

        # Try allocating a new ID gen and check that we only see position
        # advanced after we leave the context manager.

        def _get_next_txn(txn):
            stream_id = id_gen.get_next_txn(txn)
            self.assertEqual(stream_id, 8)

            self.assertEqual(id_gen.get_positions(), {"master": 7})
            self.assertEqual(id_gen.get_current_token_for_writer("master"), 7)

        self.get_success(self.db_pool.runInteraction("test", _get_next_txn))

        self.assertEqual(id_gen.get_positions(), {"master": 8})
        self.assertEqual(id_gen.get_current_token_for_writer("master"), 8)

    def test_get_persisted_upto_position(self):
        """Test that `get_persisted_upto_position` correctly tracks updates to
        positions.
        """

        # The following tests are a bit cheeky in that we notify about new
        # positions via `advance` without *actually* advancing the postgres
        # sequence.

        self._insert_row_with_id("first", 3)
        self._insert_row_with_id("second", 5)

        id_gen = self._create_id_generator("first")

        self.assertEqual(id_gen.get_positions(), {"first": 3, "second": 5})

        # Min is 3 and there is a gap between 5, so we expect it to be 3.
        self.assertEqual(id_gen.get_persisted_upto_position(), 3)

        # We advance "first" straight to 6. Min is now 5 but there is no gap so
        # we expect it to be 6
        id_gen.advance("first", 6)
        self.assertEqual(id_gen.get_persisted_upto_position(), 6)

        # No gap, so we expect 7.
        id_gen.advance("second", 7)
        self.assertEqual(id_gen.get_persisted_upto_position(), 7)

        # We haven't seen 8 yet, so we expect 7 still.
        id_gen.advance("second", 9)
        self.assertEqual(id_gen.get_persisted_upto_position(), 7)

        # Now that we've seen 7, 8 and 9 we can got straight to 9.
        id_gen.advance("first", 8)
        self.assertEqual(id_gen.get_persisted_upto_position(), 9)

        # Jump forward with gaps. The minimum is 11, even though we haven't seen
        # 10 we know that everything before 11 must be persisted.
        id_gen.advance("first", 11)
        id_gen.advance("second", 15)
        self.assertEqual(id_gen.get_persisted_upto_position(), 11)

    def test_get_persisted_upto_position_get_next(self):
        """Test that `get_persisted_upto_position` correctly tracks updates to
        positions when `get_next` is called.
        """

        self._insert_row_with_id("first", 3)
        self._insert_row_with_id("second", 5)

        id_gen = self._create_id_generator("first")

        self.assertEqual(id_gen.get_positions(), {"first": 3, "second": 5})

        self.assertEqual(id_gen.get_persisted_upto_position(), 3)
        with self.get_success(id_gen.get_next()) as stream_id:
            self.assertEqual(stream_id, 6)
            self.assertEqual(id_gen.get_persisted_upto_position(), 3)

        self.assertEqual(id_gen.get_persisted_upto_position(), 6)

        # We assume that so long as `get_next` does correctly advance the
        # `persisted_upto_position` in this case, then it will be correct in the
        # other cases that are tested above (since they'll hit the same code).


class BackwardsMultiWriterIdGeneratorTestCase(HomeserverTestCase):
    """Tests MultiWriterIdGenerator that produce *negative* stream IDs.
    """

    if not USE_POSTGRES_FOR_TESTS:
        skip = "Requires Postgres"

    def prepare(self, reactor, clock, hs):
        self.store = hs.get_datastore()
        self.db_pool = self.store.db_pool  # type: DatabasePool

        self.get_success(self.db_pool.runInteraction("_setup_db", self._setup_db))

    def _setup_db(self, txn):
        txn.execute("CREATE SEQUENCE foobar_seq")
        txn.execute(
            """
            CREATE TABLE foobar (
                stream_id BIGINT NOT NULL,
                instance_name TEXT NOT NULL,
                data TEXT
            );
            """
        )

    def _create_id_generator(self, instance_name="master") -> MultiWriterIdGenerator:
        def _create(conn):
            return MultiWriterIdGenerator(
                conn,
                self.db_pool,
                instance_name=instance_name,
                table="foobar",
                instance_column="instance_name",
                id_column="stream_id",
                sequence_name="foobar_seq",
                positive=False,
            )

        return self.get_success(self.db_pool.runWithConnection(_create))

    def _insert_row(self, instance_name: str, stream_id: int):
        """Insert one row as the given instance with given stream_id.
        """

        def _insert(txn):
            txn.execute(
                "INSERT INTO foobar VALUES (?, ?)", (stream_id, instance_name,),
            )

        self.get_success(self.db_pool.runInteraction("_insert_row", _insert))

    def test_single_instance(self):
        """Test that reads and writes from a single process are handled
        correctly.
        """
        id_gen = self._create_id_generator()

        with self.get_success(id_gen.get_next()) as stream_id:
            self._insert_row("master", stream_id)

        self.assertEqual(id_gen.get_positions(), {"master": -1})
        self.assertEqual(id_gen.get_current_token_for_writer("master"), -1)
        self.assertEqual(id_gen.get_persisted_upto_position(), -1)

        with self.get_success(id_gen.get_next_mult(3)) as stream_ids:
            for stream_id in stream_ids:
                self._insert_row("master", stream_id)

        self.assertEqual(id_gen.get_positions(), {"master": -4})
        self.assertEqual(id_gen.get_current_token_for_writer("master"), -4)
        self.assertEqual(id_gen.get_persisted_upto_position(), -4)

        # Test loading from DB by creating a second ID gen
        second_id_gen = self._create_id_generator()

        self.assertEqual(second_id_gen.get_positions(), {"master": -4})
        self.assertEqual(second_id_gen.get_current_token_for_writer("master"), -4)
        self.assertEqual(second_id_gen.get_persisted_upto_position(), -4)

    def test_multiple_instance(self):
        """Tests that having multiple instances that get advanced over
        federation works corretly.
        """
        id_gen_1 = self._create_id_generator("first")
        id_gen_2 = self._create_id_generator("second")

        with self.get_success(id_gen_1.get_next()) as stream_id:
            self._insert_row("first", stream_id)
            id_gen_2.advance("first", stream_id)

        self.assertEqual(id_gen_1.get_positions(), {"first": -1})
        self.assertEqual(id_gen_2.get_positions(), {"first": -1})
        self.assertEqual(id_gen_1.get_persisted_upto_position(), -1)
        self.assertEqual(id_gen_2.get_persisted_upto_position(), -1)

        with self.get_success(id_gen_2.get_next()) as stream_id:
            self._insert_row("second", stream_id)
            id_gen_1.advance("second", stream_id)

        self.assertEqual(id_gen_1.get_positions(), {"first": -1, "second": -2})
        self.assertEqual(id_gen_2.get_positions(), {"first": -1, "second": -2})
        self.assertEqual(id_gen_1.get_persisted_upto_position(), -2)
        self.assertEqual(id_gen_2.get_persisted_upto_position(), -2)
