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

from typing import Callable, NoReturn, Tuple
from unittest.mock import Mock

from twisted.test.proto_helpers import MemoryReactor

from synapse.server import HomeServer
from synapse.storage.database import (
    DatabasePool,
    LoggingTransaction,
    make_tuple_comparison_clause,
)
from synapse.util import Clock

from tests import unittest


class TupleComparisonClauseTestCase(unittest.TestCase):
    def test_native_tuple_comparison(self):
        clause, args = make_tuple_comparison_clause([("a", 1), ("b", 2)])
        self.assertEqual(clause, "(a,b) > (?,?)")
        self.assertEqual(args, [1, 2])


class CallbacksTestCase(unittest.HomeserverTestCase):
    """Tests for transaction callbacks."""

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self.store = hs.get_datastores().main
        self.db_pool: DatabasePool = self.store.db_pool

    def _run_interaction(
        self, func: Callable[[LoggingTransaction, int], None]
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
        after_callback, exception_callback = self._run_interaction(lambda txn: 1 / 0)

        after_callback.assert_not_called()
        exception_callback.assert_called_once_with(987, 654, extra=321)

    def test_failed_retry(self) -> None:
        """Test that the exception callback is called for every failed attempt."""

        def _test_txn(txn: LoggingTransaction) -> NoReturn:
            """Simulate a retryable failure on every attempt."""
            raise self.db_pool.engine.module.OperationalError()

        after_callback, exception_callback = self._run_interaction(_test_txn)

        after_callback.assert_not_called()
        exception_callback.assert_has_calls(
            [
                ((987, 654), {"extra": 321}),
                ((987, 654), {"extra": 321}),
                ((987, 654), {"extra": 321}),
                ((987, 654), {"extra": 321}),
                ((987, 654), {"extra": 321}),
                ((987, 654), {"extra": 321}),
            ]
        )
        self.assertEqual(exception_callback.call_count, 6)  # no additional calls

    def test_successful_retry(self) -> None:
        """Test callbacks for a failed transaction followed by a successful attempt."""
        first_attempt = True

        def _test_txn(txn: LoggingTransaction) -> None:
            """Simulate a retryable failure on the first attempt only."""
            nonlocal first_attempt
            if first_attempt:
                first_attempt = False
                raise self.db_pool.engine.module.OperationalError()
            else:
                return None

        after_callback, exception_callback = self._run_interaction(_test_txn)

        # Calling both `after_callback`s when the first attempt failed is rather
        # dubious. But let's document the behaviour in a test.
        after_callback.assert_has_calls(
            [
                ((123, 456), {"extra": 789}),
                ((123, 456), {"extra": 789}),
            ]
        )
        self.assertEqual(after_callback.call_count, 2)  # no additional calls
        exception_callback.assert_not_called()
