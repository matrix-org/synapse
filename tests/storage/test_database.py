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

from typing import Callable, List, Tuple
from unittest.mock import Mock, call

from twisted.internet import defer
from twisted.internet.defer import CancelledError, Deferred
from twisted.test.proto_helpers import MemoryReactor

from synapse.server import HomeServer
from synapse.storage.database import (
    DatabasePool,
    LoggingDatabaseConnection,
    LoggingTransaction,
    make_tuple_comparison_clause,
)
from synapse.util import Clock

from tests import unittest
from tests.utils import USE_POSTGRES_FOR_TESTS


class TupleComparisonClauseTestCase(unittest.TestCase):
    def test_native_tuple_comparison(self) -> None:
        clause, args = make_tuple_comparison_clause([("a", 1), ("b", 2)])
        self.assertEqual(clause, "(a,b) > (?,?)")
        self.assertEqual(args, [1, 2])


class ExecuteScriptTestCase(unittest.HomeserverTestCase):
    """Tests for `BaseDatabaseEngine.executescript` implementations."""

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self.store = hs.get_datastores().main
        self.db_pool: DatabasePool = self.store.db_pool
        self.get_success(
            self.db_pool.runInteraction(
                "create",
                lambda txn: txn.execute("CREATE TABLE foo (name TEXT PRIMARY KEY)"),
            )
        )

    def test_transaction(self) -> None:
        """Test that all statements are run in a single transaction."""

        def run(conn: LoggingDatabaseConnection) -> None:
            cur = conn.cursor(txn_name="test_transaction")
            self.db_pool.engine.executescript(
                cur,
                ";".join(
                    [
                        "INSERT INTO foo (name) VALUES ('transaction test')",
                        # This next statement will fail. When `executescript` is not
                        # transactional, the previous row will be observed later.
                        "INSERT INTO foo (name) VALUES ('transaction test')",
                    ]
                ),
            )

        self.get_failure(
            self.db_pool.runWithConnection(run),
            self.db_pool.engine.module.IntegrityError,
        )

        self.assertIsNone(
            self.get_success(
                self.db_pool.simple_select_one_onecol(
                    "foo",
                    keyvalues={"name": "transaction test"},
                    retcol="name",
                    allow_none=True,
                )
            ),
            "executescript is not running statements inside a transaction",
        )

    def test_commit(self) -> None:
        """Test that the script transaction remains open and can be committed."""

        def run(conn: LoggingDatabaseConnection) -> None:
            cur = conn.cursor(txn_name="test_commit")
            self.db_pool.engine.executescript(
                cur, "INSERT INTO foo (name) VALUES ('commit test')"
            )
            cur.execute("COMMIT")

        self.get_success(self.db_pool.runWithConnection(run))

        self.assertIsNotNone(
            self.get_success(
                self.db_pool.simple_select_one_onecol(
                    "foo",
                    keyvalues={"name": "commit test"},
                    retcol="name",
                    allow_none=True,
                )
            ),
        )

    def test_rollback(self) -> None:
        """Test that the script transaction remains open and can be rolled back."""

        def run(conn: LoggingDatabaseConnection) -> None:
            cur = conn.cursor(txn_name="test_rollback")
            self.db_pool.engine.executescript(
                cur, "INSERT INTO foo (name) VALUES ('rollback test')"
            )
            cur.execute("ROLLBACK")

        self.get_success(self.db_pool.runWithConnection(run))

        self.assertIsNone(
            self.get_success(
                self.db_pool.simple_select_one_onecol(
                    "foo",
                    keyvalues={"name": "rollback test"},
                    retcol="name",
                    allow_none=True,
                )
            ),
            "executescript is not leaving the script transaction open",
        )


class CallbacksTestCase(unittest.HomeserverTestCase):
    """Tests for transaction callbacks."""

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self.store = hs.get_datastores().main
        self.db_pool: DatabasePool = self.store.db_pool

    def _run_interaction(
        self, func: Callable[[LoggingTransaction], object]
    ) -> Tuple[Mock, Mock]:
        """Run the given function in a database transaction, with callbacks registered.

        Args:
            func: The function to be run in a transaction. The transaction will be
                retried if `func` raises an `OperationalError`.

        Returns:
            Two mocks, which were registered as an `after_callback` and an
            `exception_callback` respectively, on every transaction attempt.
        """
        after_callback = Mock()
        exception_callback = Mock()

        def _test_txn(txn: LoggingTransaction) -> None:
            txn.call_after(after_callback, 123, 456, extra=789)
            txn.call_on_exception(exception_callback, 987, 654, extra=321)
            func(txn)

        try:
            self.get_success_or_raise(
                self.db_pool.runInteraction("test_transaction", _test_txn)
            )
        except Exception:
            pass

        return after_callback, exception_callback

    def test_after_callback(self) -> None:
        """Test that the after callback is called when a transaction succeeds."""
        after_callback, exception_callback = self._run_interaction(lambda txn: None)

        after_callback.assert_called_once_with(123, 456, extra=789)
        exception_callback.assert_not_called()

    def test_exception_callback(self) -> None:
        """Test that the exception callback is called when a transaction fails."""
        _test_txn = Mock(side_effect=ZeroDivisionError)
        after_callback, exception_callback = self._run_interaction(_test_txn)

        after_callback.assert_not_called()
        exception_callback.assert_called_once_with(987, 654, extra=321)

    def test_failed_retry(self) -> None:
        """Test that the exception callback is called for every failed attempt."""
        # Always raise an `OperationalError`.
        _test_txn = Mock(side_effect=self.db_pool.engine.module.OperationalError)
        after_callback, exception_callback = self._run_interaction(_test_txn)

        after_callback.assert_not_called()
        exception_callback.assert_has_calls(
            [
                call(987, 654, extra=321),
                call(987, 654, extra=321),
                call(987, 654, extra=321),
                call(987, 654, extra=321),
                call(987, 654, extra=321),
                call(987, 654, extra=321),
            ]
        )
        self.assertEqual(exception_callback.call_count, 6)  # no additional calls

    def test_successful_retry(self) -> None:
        """Test callbacks for a failed transaction followed by a successful attempt."""
        # Raise an `OperationalError` on the first attempt only.
        _test_txn = Mock(
            side_effect=[self.db_pool.engine.module.OperationalError, None]
        )
        after_callback, exception_callback = self._run_interaction(_test_txn)

        # Calling both `after_callback`s when the first attempt failed is rather
        # surprising (#12184). Let's document the behaviour in a test.
        after_callback.assert_has_calls(
            [
                call(123, 456, extra=789),
                call(123, 456, extra=789),
            ]
        )
        self.assertEqual(after_callback.call_count, 2)  # no additional calls
        exception_callback.assert_not_called()


class CancellationTestCase(unittest.HomeserverTestCase):
    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self.store = hs.get_datastores().main
        self.db_pool: DatabasePool = self.store.db_pool

    def test_after_callback(self) -> None:
        """Test that the after callback is called when a transaction succeeds."""
        d: "Deferred[None]"
        after_callback = Mock()
        exception_callback = Mock()

        def _test_txn(txn: LoggingTransaction) -> None:
            txn.call_after(after_callback, 123, 456, extra=789)
            txn.call_on_exception(exception_callback, 987, 654, extra=321)
            d.cancel()

        d = defer.ensureDeferred(
            self.db_pool.runInteraction("test_transaction", _test_txn)
        )
        self.get_failure(d, CancelledError)

        after_callback.assert_called_once_with(123, 456, extra=789)
        exception_callback.assert_not_called()

    def test_exception_callback(self) -> None:
        """Test that the exception callback is called when a transaction fails."""
        d: "Deferred[None]"
        after_callback = Mock()
        exception_callback = Mock()

        def _test_txn(txn: LoggingTransaction) -> None:
            txn.call_after(after_callback, 123, 456, extra=789)
            txn.call_on_exception(exception_callback, 987, 654, extra=321)
            d.cancel()
            # Simulate a retryable failure on every attempt.
            raise self.db_pool.engine.module.OperationalError()

        d = defer.ensureDeferred(
            self.db_pool.runInteraction("test_transaction", _test_txn)
        )
        self.get_failure(d, CancelledError)

        after_callback.assert_not_called()
        exception_callback.assert_has_calls(
            [
                call(987, 654, extra=321),
                call(987, 654, extra=321),
                call(987, 654, extra=321),
                call(987, 654, extra=321),
                call(987, 654, extra=321),
                call(987, 654, extra=321),
            ]
        )
        self.assertEqual(exception_callback.call_count, 6)  # no additional calls


class PostgresReplicaIdentityTestCase(unittest.HomeserverTestCase):
    if not USE_POSTGRES_FOR_TESTS:
        skip = "Requires Postgres"

    def prepare(
        self, reactor: MemoryReactor, clock: Clock, homeserver: HomeServer
    ) -> None:
        self.db_pools = homeserver.get_datastores().databases

    def test_all_tables_have_postgres_replica_identity(self) -> None:
        """
        Tests that all tables have a Postgres REPLICA IDENTITY.
        (See #16224).

        Tables with a PRIMARY KEY have an implied REPLICA IDENTITY and are fine.
        Other tables need them to be set with `ALTER TABLE`.

        A REPLICA IDENTITY is required for Postgres logical replication to work
        properly without blocking updates and deletes.
        """

        sql = """
            -- Select tables that have no primary key and use the default replica identity rule
            -- (the default is to use the primary key)
            WITH tables_no_pkey AS (
                SELECT tbl.table_schema, tbl.table_name
                FROM information_schema.tables tbl
                WHERE table_type = 'BASE TABLE'
                    AND table_schema not in ('pg_catalog', 'information_schema')
                    AND NOT EXISTS (
                        SELECT 1
                        FROM information_schema.key_column_usage kcu
                        WHERE kcu.table_name = tbl.table_name
                            AND kcu.table_schema = tbl.table_schema
                    )
            )
            SELECT oid::regclass FROM tables_no_pkey INNER JOIN pg_class ON oid::regclass = table_name::regclass
            WHERE relreplident = 'd'

            UNION

            -- Also select tables that use an index as a replica identity
            -- but where the index doesn't exist
            -- (e.g. it could have been deleted)
            SELECT oid::regclass
                FROM information_schema.tables tbl
                INNER JOIN pg_class ON oid::regclass = table_name::regclass
                WHERE table_type = 'BASE TABLE'
                    AND table_schema not in ('pg_catalog', 'information_schema')

                    -- 'i' means an index is used as the replica identity
                    AND relreplident = 'i'

                    -- look for indices that are marked as the replica identity
                    AND NOT EXISTS (
                        SELECT indexrelid::regclass
                        FROM pg_index
                        WHERE indrelid = oid::regclass AND indisreplident
                    )
        """

        def _list_tables_with_missing_replica_identities_txn(
            txn: LoggingTransaction,
        ) -> List[str]:
            txn.execute(sql)
            return [table_name for table_name, in txn]

        for pool in self.db_pools:
            missing = self.get_success(
                pool.runInteraction(
                    "test_list_missing_replica_identities",
                    _list_tables_with_missing_replica_identities_txn,
                )
            )
            self.assertTrue(
                len(missing) == 0,
                f"The following tables in the {pool.name()!r} database are missing REPLICA IDENTITIES: {missing!r}.",
            )
