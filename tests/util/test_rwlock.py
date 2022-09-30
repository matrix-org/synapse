# Copyright 2016 OpenMarket Ltd
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

from typing import AsyncContextManager, Callable, Sequence, Tuple

from twisted.internet import defer
from twisted.internet.defer import CancelledError, Deferred

from synapse.util.async_helpers import ReadWriteLock

from tests import unittest


class ReadWriteLockTestCase(unittest.TestCase):
    def _start_reader_or_writer(
        self,
        read_or_write: Callable[[str], AsyncContextManager],
        key: str,
        return_value: str,
    ) -> Tuple["Deferred[str]", "Deferred[None]", "Deferred[None]"]:
        """Starts a reader or writer which acquires the lock, blocks, then completes.

        Args:
            read_or_write: A function returning a context manager for a lock.
                Either a bound `ReadWriteLock.read` or `ReadWriteLock.write`.
            key: The key to read or write.
            return_value: A string that the reader or writer will resolve with when
                done.

        Returns:
            A tuple of three `Deferred`s:
             * A cancellable `Deferred` for the entire read or write operation that
               resolves with `return_value` on successful completion.
             * A `Deferred` that resolves once the reader or writer acquires the lock.
             * A `Deferred` that blocks the reader or writer. Must be resolved by the
               caller to allow the reader or writer to release the lock and complete.
        """
        acquired_d: "Deferred[None]" = Deferred()
        unblock_d: "Deferred[None]" = Deferred()

        async def reader_or_writer():
            async with read_or_write(key):
                acquired_d.callback(None)
                await unblock_d
            return return_value

        d = defer.ensureDeferred(reader_or_writer())
        return d, acquired_d, unblock_d

    def _start_blocking_reader(
        self, rwlock: ReadWriteLock, key: str, return_value: str
    ) -> Tuple["Deferred[str]", "Deferred[None]", "Deferred[None]"]:
        """Starts a reader which acquires the lock, blocks, then releases the lock.

        See the docstring for `_start_reader_or_writer` for details about the arguments
        and return values.
        """
        return self._start_reader_or_writer(rwlock.read, key, return_value)

    def _start_blocking_writer(
        self, rwlock: ReadWriteLock, key: str, return_value: str
    ) -> Tuple["Deferred[str]", "Deferred[None]", "Deferred[None]"]:
        """Starts a writer which acquires the lock, blocks, then releases the lock.

        See the docstring for `_start_reader_or_writer` for details about the arguments
        and return values.
        """
        return self._start_reader_or_writer(rwlock.write, key, return_value)

    def _start_nonblocking_reader(
        self, rwlock: ReadWriteLock, key: str, return_value: str
    ) -> Tuple["Deferred[str]", "Deferred[None]"]:
        """Starts a reader which acquires the lock, then releases it immediately.

        See the docstring for `_start_reader_or_writer` for details about the arguments.

        Returns:
            A tuple of two `Deferred`s:
             * A cancellable `Deferred` for the entire read operation that resolves with
               `return_value` on successful completion.
             * A `Deferred` that resolves once the reader acquires the lock.
        """
        d, acquired_d, unblock_d = self._start_reader_or_writer(
            rwlock.read, key, return_value
        )
        unblock_d.callback(None)
        return d, acquired_d

    def _start_nonblocking_writer(
        self, rwlock: ReadWriteLock, key: str, return_value: str
    ) -> Tuple["Deferred[str]", "Deferred[None]"]:
        """Starts a writer which acquires the lock, then releases it immediately.

        See the docstring for `_start_reader_or_writer` for details about the arguments.

        Returns:
            A tuple of two `Deferred`s:
             * A cancellable `Deferred` for the entire write operation that resolves
               with `return_value` on successful completion.
             * A `Deferred` that resolves once the writer acquires the lock.
        """
        d, acquired_d, unblock_d = self._start_reader_or_writer(
            rwlock.write, key, return_value
        )
        unblock_d.callback(None)
        return d, acquired_d

    def _assert_first_n_resolved(
        self, deferreds: Sequence["defer.Deferred[None]"], n: int
    ) -> None:
        """Assert that exactly the first n `Deferred`s in the given list are resolved.

        Args:
            deferreds: The list of `Deferred`s to be checked.
            n: The number of `Deferred`s at the start of `deferreds` that should be
                resolved.
        """
        for i, d in enumerate(deferreds[:n]):
            self.assertTrue(d.called, msg="deferred %d was unexpectedly unresolved" % i)

        for i, d in enumerate(deferreds[n:]):
            self.assertFalse(
                d.called, msg="deferred %d was unexpectedly resolved" % (i + n)
            )

    def test_rwlock(self):
        rwlock = ReadWriteLock()
        key = "key"

        ds = [
            self._start_blocking_reader(rwlock, key, "0"),
            self._start_blocking_reader(rwlock, key, "1"),
            self._start_blocking_writer(rwlock, key, "2"),
            self._start_blocking_writer(rwlock, key, "3"),
            self._start_blocking_reader(rwlock, key, "4"),
            self._start_blocking_reader(rwlock, key, "5"),
            self._start_blocking_writer(rwlock, key, "6"),
        ]
        # `Deferred`s that resolve when each reader or writer acquires the lock.
        acquired_ds = [acquired_d for _, acquired_d, _ in ds]
        # `Deferred`s that will trigger the release of locks when resolved.
        release_ds = [release_d for _, _, release_d in ds]

        # The first two readers should acquire their locks.
        self._assert_first_n_resolved(acquired_ds, 2)

        # Release one of the read locks. The next writer should not acquire the lock,
        # because there is another reader holding the lock.
        self._assert_first_n_resolved(acquired_ds, 2)
        release_ds[0].callback(None)
        self._assert_first_n_resolved(acquired_ds, 2)

        # Release the other read lock. The next writer should acquire the lock.
        self._assert_first_n_resolved(acquired_ds, 2)
        release_ds[1].callback(None)
        self._assert_first_n_resolved(acquired_ds, 3)

        # Release the write lock. The next writer should acquire the lock.
        self._assert_first_n_resolved(acquired_ds, 3)
        release_ds[2].callback(None)
        self._assert_first_n_resolved(acquired_ds, 4)

        # Release the write lock. The next two readers should acquire locks.
        self._assert_first_n_resolved(acquired_ds, 4)
        release_ds[3].callback(None)
        self._assert_first_n_resolved(acquired_ds, 6)

        # Release one of the read locks. The next writer should not acquire the lock,
        # because there is another reader holding the lock.
        self._assert_first_n_resolved(acquired_ds, 6)
        release_ds[5].callback(None)
        self._assert_first_n_resolved(acquired_ds, 6)

        # Release the other read lock. The next writer should acquire the lock.
        self._assert_first_n_resolved(acquired_ds, 6)
        release_ds[4].callback(None)
        self._assert_first_n_resolved(acquired_ds, 7)

        # Release the write lock.
        release_ds[6].callback(None)

        # Acquire and release the write and read locks one last time for good measure.
        _, acquired_d = self._start_nonblocking_writer(rwlock, key, "last writer")
        self.assertTrue(acquired_d.called)

        _, acquired_d = self._start_nonblocking_reader(rwlock, key, "last reader")
        self.assertTrue(acquired_d.called)

    def test_lock_handoff_to_nonblocking_writer(self):
        """Test a writer handing the lock to another writer that completes instantly."""
        rwlock = ReadWriteLock()
        key = "key"

        d1, _, unblock = self._start_blocking_writer(rwlock, key, "write 1 completed")
        d2, _ = self._start_nonblocking_writer(rwlock, key, "write 2 completed")
        self.assertFalse(d1.called)
        self.assertFalse(d2.called)

        # Unblock the first writer. The second writer will complete without blocking.
        unblock.callback(None)
        self.assertTrue(d1.called)
        self.assertTrue(d2.called)

        # The `ReadWriteLock` should operate as normal.
        d3, _ = self._start_nonblocking_writer(rwlock, key, "write 3 completed")
        self.assertTrue(d3.called)

    def test_cancellation_while_holding_read_lock(self):
        """Test cancellation while holding a read lock.

        A waiting writer should be given the lock when the reader holding the lock is
        cancelled.
        """
        rwlock = ReadWriteLock()
        key = "key"

        # 1. A reader takes the lock and blocks.
        reader_d, _, _ = self._start_blocking_reader(rwlock, key, "read completed")

        # 2. A writer waits for the reader to complete.
        writer_d, _ = self._start_nonblocking_writer(rwlock, key, "write completed")
        self.assertFalse(writer_d.called)

        # 3. The reader is cancelled.
        reader_d.cancel()
        self.failureResultOf(reader_d, CancelledError)

        # 4. The writer should take the lock and complete.
        self.assertTrue(
            writer_d.called, "Writer is stuck waiting for a cancelled reader"
        )
        self.assertEqual("write completed", self.successResultOf(writer_d))

    def test_cancellation_while_holding_write_lock(self):
        """Test cancellation while holding a write lock.

        A waiting reader should be given the lock when the writer holding the lock is
        cancelled.
        """
        rwlock = ReadWriteLock()
        key = "key"

        # 1. A writer takes the lock and blocks.
        writer_d, _, _ = self._start_blocking_writer(rwlock, key, "write completed")

        # 2. A reader waits for the writer to complete.
        reader_d, _ = self._start_nonblocking_reader(rwlock, key, "read completed")
        self.assertFalse(reader_d.called)

        # 3. The writer is cancelled.
        writer_d.cancel()
        self.failureResultOf(writer_d, CancelledError)

        # 4. The reader should take the lock and complete.
        self.assertTrue(
            reader_d.called, "Reader is stuck waiting for a cancelled writer"
        )
        self.assertEqual("read completed", self.successResultOf(reader_d))

    def test_cancellation_while_waiting_for_read_lock(self):
        """Test cancellation while waiting for a read lock.

        Tests that cancelling a waiting reader:
         * does not cancel the writer it is waiting on
         * does not cancel the next writer waiting on it
         * does not allow the next writer to acquire the lock before an earlier writer
           has finished
         * does not keep the next writer waiting indefinitely

        These correspond to the asserts with explicit messages.
        """
        rwlock = ReadWriteLock()
        key = "key"

        # 1. A writer takes the lock and blocks.
        writer1_d, _, unblock_writer1 = self._start_blocking_writer(
            rwlock, key, "write 1 completed"
        )

        # 2. A reader waits for the first writer to complete.
        #    This reader will be cancelled later.
        reader_d, _ = self._start_nonblocking_reader(rwlock, key, "read completed")
        self.assertFalse(reader_d.called)

        # 3. A second writer waits for both the first writer and the reader to complete.
        writer2_d, _ = self._start_nonblocking_writer(rwlock, key, "write 2 completed")
        self.assertFalse(writer2_d.called)

        # 4. The waiting reader is cancelled.
        #    Neither of the writers should be cancelled.
        #    The second writer should still be waiting, but only on the first writer.
        reader_d.cancel()
        self.failureResultOf(reader_d, CancelledError)
        self.assertFalse(writer1_d.called, "First writer was unexpectedly cancelled")
        self.assertFalse(
            writer2_d.called,
            "Second writer was unexpectedly cancelled or given the lock before the "
            "first writer finished",
        )

        # 5. Unblock the first writer, which should complete.
        unblock_writer1.callback(None)
        self.assertEqual("write 1 completed", self.successResultOf(writer1_d))

        # 6. The second writer should take the lock and complete.
        self.assertTrue(
            writer2_d.called, "Second writer is stuck waiting for a cancelled reader"
        )
        self.assertEqual("write 2 completed", self.successResultOf(writer2_d))

    def test_cancellation_while_waiting_for_write_lock(self):
        """Test cancellation while waiting for a write lock.

        Tests that cancelling a waiting writer:
         * does not cancel the reader or writer it is waiting on
         * does not cancel the next writer waiting on it
         * does not allow the next writer to acquire the lock before an earlier reader
           and writer have finished
         * does not keep the next writer waiting indefinitely

        These correspond to the asserts with explicit messages.
        """
        rwlock = ReadWriteLock()
        key = "key"

        # 1. A reader takes the lock and blocks.
        reader_d, _, unblock_reader = self._start_blocking_reader(
            rwlock, key, "read completed"
        )

        # 2. A writer waits for the reader to complete.
        writer1_d, _, unblock_writer1 = self._start_blocking_writer(
            rwlock, key, "write 1 completed"
        )

        # 3. A second writer waits for both the reader and first writer to complete.
        #    This writer will be cancelled later.
        writer2_d, _ = self._start_nonblocking_writer(rwlock, key, "write 2 completed")
        self.assertFalse(writer2_d.called)

        # 4. A third writer waits for the second writer to complete.
        writer3_d, _ = self._start_nonblocking_writer(rwlock, key, "write 3 completed")
        self.assertFalse(writer3_d.called)

        # 5. The second writer is cancelled, but continues waiting for the lock.
        #    The reader, first writer and third writer should not be cancelled.
        #    The first writer should still be waiting on the reader.
        #    The third writer should still be waiting on the second writer.
        writer2_d.cancel()
        self.assertNoResult(writer2_d)
        self.assertFalse(reader_d.called, "Reader was unexpectedly cancelled")
        self.assertFalse(writer1_d.called, "First writer was unexpectedly cancelled")
        self.assertFalse(
            writer3_d.called,
            "Third writer was unexpectedly cancelled or given the lock before the first "
            "writer finished",
        )

        # 6. Unblock the reader, which should complete.
        #    The first writer should be given the lock and block.
        #    The third writer should still be waiting on the second writer.
        unblock_reader.callback(None)
        self.assertEqual("read completed", self.successResultOf(reader_d))
        self.assertNoResult(writer2_d)
        self.assertFalse(
            writer3_d.called,
            "Third writer was unexpectedly given the lock before the first writer "
            "finished",
        )

        # 7. Unblock the first writer, which should complete.
        unblock_writer1.callback(None)
        self.assertEqual("write 1 completed", self.successResultOf(writer1_d))

        # 8. The second writer should take the lock and release it immediately, since it
        #    has been cancelled.
        self.failureResultOf(writer2_d, CancelledError)

        # 9. The third writer should take the lock and complete.
        self.assertTrue(
            writer3_d.called, "Third writer is stuck waiting for a cancelled writer"
        )
        self.assertEqual("write 3 completed", self.successResultOf(writer3_d))
