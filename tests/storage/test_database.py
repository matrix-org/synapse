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

from typing import Callable, Tuple
from unittest.mock import Mock, call

from twisted.internet import defer
from twisted.internet.defer import CancelledError, Deferred
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
