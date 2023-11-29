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


from twisted.internet import defer, reactor
from twisted.internet.base import ReactorBase
from twisted.internet.defer import Deferred
from twisted.test.proto_helpers import MemoryReactor

from synapse.server import HomeServer
from synapse.storage.databases.main.lock import _LOCK_TIMEOUT_MS, _RENEWAL_INTERVAL_MS
from synapse.util import Clock

from tests import unittest


class LockTestCase(unittest.HomeserverTestCase):
    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self.store = hs.get_datastores().main

    def test_acquire_contention(self) -> None:
        # Track the number of tasks holding the lock.
        # Should be at most 1.
        in_lock = 0
        max_in_lock = 0

        release_lock: "Deferred[None]" = Deferred()

        async def task() -> None:
            nonlocal in_lock
            nonlocal max_in_lock

            lock = await self.store.try_acquire_lock("name", "key")
            if not lock:
                return

            async with lock:
                in_lock += 1
                max_in_lock = max(max_in_lock, in_lock)

                # Block to allow other tasks to attempt to take the lock.
                await release_lock

                in_lock -= 1

        # Start 3 tasks.
        task1 = defer.ensureDeferred(task())
        task2 = defer.ensureDeferred(task())
        task3 = defer.ensureDeferred(task())

        # Give the reactor a kick so that the database transaction returns.
        self.pump()

        release_lock.callback(None)

        # Run the tasks to completion.
        # To work around `Linearizer`s using a different reactor to sleep when
        # contended (https://github.com/matrix-org/synapse/issues/12841), we call
        # `runUntilCurrent` on `twisted.internet.reactor`, which is a different
        # reactor to that used by the homeserver.
        assert isinstance(reactor, ReactorBase)
        self.get_success(task1)
        reactor.runUntilCurrent()
        self.get_success(task2)
        reactor.runUntilCurrent()
        self.get_success(task3)

        # At most one task should have held the lock at a time.
        self.assertEqual(max_in_lock, 1)

    def test_simple_lock(self) -> None:
        """Test that we can take out a lock and that while we hold it nobody
        else can take it out.
        """
        # First to acquire this lock, so it should complete
        lock = self.get_success(self.store.try_acquire_lock("name", "key"))
        assert lock is not None

        # Enter the context manager
        self.get_success(lock.__aenter__())

        # Attempting to acquire the lock again fails.
        lock2 = self.get_success(self.store.try_acquire_lock("name", "key"))
        self.assertIsNone(lock2)

        # Calling `is_still_valid` reports true.
        self.assertTrue(self.get_success(lock.is_still_valid()))

        # Drop the lock
        self.get_success(lock.__aexit__(None, None, None))

        # We can now acquire the lock again.
        lock3 = self.get_success(self.store.try_acquire_lock("name", "key"))
        assert lock3 is not None
        self.get_success(lock3.__aenter__())
        self.get_success(lock3.__aexit__(None, None, None))

    def test_maintain_lock(self) -> None:
        """Test that we don't time out locks while they're still active"""

        lock = self.get_success(self.store.try_acquire_lock("name", "key"))
        assert lock is not None

        self.get_success(lock.__aenter__())

        # Wait for ages with the lock, we should not be able to get the lock.
        self.reactor.advance(5 * _LOCK_TIMEOUT_MS / 1000)

        lock2 = self.get_success(self.store.try_acquire_lock("name", "key"))
        self.assertIsNone(lock2)

        self.get_success(lock.__aexit__(None, None, None))

    def test_timeout_lock(self) -> None:
        """Test that we time out locks if they're not updated for ages"""

        lock = self.get_success(self.store.try_acquire_lock("name", "key"))
        assert lock is not None

        self.get_success(lock.__aenter__())

        # We simulate the process getting stuck by cancelling the looping call
        # that keeps the lock active.
        assert lock._looping_call
        lock._looping_call.stop()

        # Wait for the lock to timeout.
        self.reactor.advance(2 * _LOCK_TIMEOUT_MS / 1000)

        lock2 = self.get_success(self.store.try_acquire_lock("name", "key"))
        self.assertIsNotNone(lock2)

        self.assertFalse(self.get_success(lock.is_still_valid()))

    def test_drop(self) -> None:
        """Test that dropping the context manager means we stop renewing the lock"""

        lock = self.get_success(self.store.try_acquire_lock("name", "key"))
        self.assertIsNotNone(lock)

        del lock

        # Wait for the lock to timeout.
        self.reactor.advance(2 * _LOCK_TIMEOUT_MS / 1000)

        lock2 = self.get_success(self.store.try_acquire_lock("name", "key"))
        self.assertIsNotNone(lock2)

    def test_shutdown(self) -> None:
        """Test that shutting down Synapse releases the locks"""
        # Acquire two locks
        lock = self.get_success(self.store.try_acquire_lock("name", "key1"))
        self.assertIsNotNone(lock)
        lock2 = self.get_success(self.store.try_acquire_lock("name", "key2"))
        self.assertIsNotNone(lock2)

        # Now call the shutdown code
        self.get_success(self.store._on_shutdown())

        self.assertEqual(self.store._live_lock_tokens, {})


class ReadWriteLockTestCase(unittest.HomeserverTestCase):
    """Test the read/write lock implementation."""

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self.store = hs.get_datastores().main

    def test_acquire_write_contention(self) -> None:
        """Test that we can only acquire one write lock at a time"""
        # Track the number of tasks holding the lock.
        # Should be at most 1.
        in_lock = 0
        max_in_lock = 0

        release_lock: "Deferred[None]" = Deferred()

        async def task() -> None:
            nonlocal in_lock
            nonlocal max_in_lock

            lock = await self.store.try_acquire_read_write_lock(
                "name", "key", write=True
            )
            if not lock:
                return

            async with lock:
                in_lock += 1
                max_in_lock = max(max_in_lock, in_lock)

                # Block to allow other tasks to attempt to take the lock.
                await release_lock

                in_lock -= 1

        # Start 3 tasks.
        task1 = defer.ensureDeferred(task())
        task2 = defer.ensureDeferred(task())
        task3 = defer.ensureDeferred(task())

        # Give the reactor a kick so that the database transaction returns.
        self.pump()

        release_lock.callback(None)

        # Run the tasks to completion.
        # To work around `Linearizer`s using a different reactor to sleep when
        # contended (https://github.com/matrix-org/synapse/issues/12841), we call
        # `runUntilCurrent` on `twisted.internet.reactor`, which is a different
        # reactor to that used by the homeserver.
        assert isinstance(reactor, ReactorBase)
        self.get_success(task1)
        reactor.runUntilCurrent()
        self.get_success(task2)
        reactor.runUntilCurrent()
        self.get_success(task3)

        # At most one task should have held the lock at a time.
        self.assertEqual(max_in_lock, 1)

    def test_acquire_multiple_reads(self) -> None:
        """Test that we can acquire multiple read locks at a time"""
        # Track the number of tasks holding the lock.
        in_lock = 0
        max_in_lock = 0

        release_lock: "Deferred[None]" = Deferred()

        async def task() -> None:
            nonlocal in_lock
            nonlocal max_in_lock

            lock = await self.store.try_acquire_read_write_lock(
                "name", "key", write=False
            )
            if not lock:
                return

            async with lock:
                in_lock += 1
                max_in_lock = max(max_in_lock, in_lock)

                # Block to allow other tasks to attempt to take the lock.
                await release_lock

                in_lock -= 1

        # Start 3 tasks.
        task1 = defer.ensureDeferred(task())
        task2 = defer.ensureDeferred(task())
        task3 = defer.ensureDeferred(task())

        # Give the reactor a kick so that the database transaction returns.
        self.pump()

        release_lock.callback(None)

        # Run the tasks to completion.
        # To work around `Linearizer`s using a different reactor to sleep when
        # contended (https://github.com/matrix-org/synapse/issues/12841), we call
        # `runUntilCurrent` on `twisted.internet.reactor`, which is a different
        # reactor to that used by the homeserver.
        assert isinstance(reactor, ReactorBase)
        self.get_success(task1)
        reactor.runUntilCurrent()
        self.get_success(task2)
        reactor.runUntilCurrent()
        self.get_success(task3)

        # At most one task should have held the lock at a time.
        self.assertEqual(max_in_lock, 3)

    def test_write_lock_acquired(self) -> None:
        """Test that we can take out a write lock and that while we hold it
        nobody else can take it out.
        """
        # First to acquire this lock, so it should complete
        lock = self.get_success(
            self.store.try_acquire_read_write_lock("name", "key", write=True)
        )
        assert lock is not None

        # Enter the context manager
        self.get_success(lock.__aenter__())

        # Attempting to acquire the lock again fails, as both read and write.
        lock2 = self.get_success(
            self.store.try_acquire_read_write_lock("name", "key", write=True)
        )
        self.assertIsNone(lock2)

        lock3 = self.get_success(
            self.store.try_acquire_read_write_lock("name", "key", write=False)
        )
        self.assertIsNone(lock3)

        # Calling `is_still_valid` reports true.
        self.assertTrue(self.get_success(lock.is_still_valid()))

        # Drop the lock
        self.get_success(lock.__aexit__(None, None, None))

        # We can now acquire the lock again.
        lock4 = self.get_success(
            self.store.try_acquire_read_write_lock("name", "key", write=True)
        )
        assert lock4 is not None
        self.get_success(lock4.__aenter__())
        self.get_success(lock4.__aexit__(None, None, None))

    def test_read_lock_acquired(self) -> None:
        """Test that we can take out a read lock and that while we hold it
        only other reads can use it.
        """
        # First to acquire this lock, so it should complete
        lock = self.get_success(
            self.store.try_acquire_read_write_lock("name", "key", write=False)
        )
        assert lock is not None

        # Enter the context manager
        self.get_success(lock.__aenter__())

        # Attempting to acquire the write lock fails
        lock2 = self.get_success(
            self.store.try_acquire_read_write_lock("name", "key", write=True)
        )
        self.assertIsNone(lock2)

        # Attempting to acquire a read lock succeeds
        lock3 = self.get_success(
            self.store.try_acquire_read_write_lock("name", "key", write=False)
        )
        assert lock3 is not None
        self.get_success(lock3.__aenter__())

        # Calling `is_still_valid` reports true.
        self.assertTrue(self.get_success(lock.is_still_valid()))

        # Drop the first lock
        self.get_success(lock.__aexit__(None, None, None))

        # Attempting to acquire the write lock still fails, as lock3 is still
        # active.
        lock4 = self.get_success(
            self.store.try_acquire_read_write_lock("name", "key", write=True)
        )
        self.assertIsNone(lock4)

        # Drop the still open third lock
        self.get_success(lock3.__aexit__(None, None, None))

        # We can now acquire the lock again.
        lock5 = self.get_success(
            self.store.try_acquire_read_write_lock("name", "key", write=True)
        )
        assert lock5 is not None
        self.get_success(lock5.__aenter__())
        self.get_success(lock5.__aexit__(None, None, None))

    def test_maintain_lock(self) -> None:
        """Test that we don't time out locks while they're still active (lock is
        renewed in the background if the process is still alive)"""

        lock = self.get_success(
            self.store.try_acquire_read_write_lock("name", "key", write=True)
        )
        assert lock is not None

        self.get_success(lock.__aenter__())

        # Wait for ages with the lock, we should not be able to get the lock.
        for _ in range(10):
            self.reactor.advance((_RENEWAL_INTERVAL_MS / 1000))

        lock2 = self.get_success(
            self.store.try_acquire_read_write_lock("name", "key", write=True)
        )
        self.assertIsNone(lock2)

        self.get_success(lock.__aexit__(None, None, None))

    def test_timeout_lock(self) -> None:
        """Test that we time out locks if they're not updated for ages"""

        lock = self.get_success(
            self.store.try_acquire_read_write_lock("name", "key", write=True)
        )
        assert lock is not None

        self.get_success(lock.__aenter__())

        # We simulate the process getting stuck by cancelling the looping call
        # that keeps the lock active.
        assert lock._looping_call
        lock._looping_call.stop()

        # Wait for the lock to timeout.
        self.reactor.advance(2 * _LOCK_TIMEOUT_MS / 1000)

        lock2 = self.get_success(
            self.store.try_acquire_read_write_lock("name", "key", write=True)
        )
        self.assertIsNotNone(lock2)

        self.assertFalse(self.get_success(lock.is_still_valid()))

    def test_drop(self) -> None:
        """Test that dropping the context manager means we stop renewing the lock"""

        lock = self.get_success(
            self.store.try_acquire_read_write_lock("name", "key", write=True)
        )
        self.assertIsNotNone(lock)

        del lock

        # Wait for the lock to timeout.
        self.reactor.advance(2 * _LOCK_TIMEOUT_MS / 1000)

        lock2 = self.get_success(
            self.store.try_acquire_read_write_lock("name", "key", write=True)
        )
        self.assertIsNotNone(lock2)

    def test_shutdown(self) -> None:
        """Test that shutting down Synapse releases the locks"""
        # Acquire two locks
        lock = self.get_success(
            self.store.try_acquire_read_write_lock("name", "key", write=True)
        )
        self.assertIsNotNone(lock)
        lock2 = self.get_success(
            self.store.try_acquire_read_write_lock("name", "key2", write=True)
        )
        self.assertIsNotNone(lock2)

        # Now call the shutdown code
        self.get_success(self.store._on_shutdown())

        self.assertEqual(self.store._live_read_write_lock_tokens, {})

    def test_acquire_multiple_locks(self) -> None:
        """Tests that acquiring multiple locks at once works."""

        # Take out multiple locks and ensure that we can't get those locks out
        # again.
        lock = self.get_success(
            self.store.try_acquire_multi_read_write_lock(
                [("name1", "key1"), ("name2", "key2")], write=True
            )
        )
        self.assertIsNotNone(lock)

        assert lock is not None
        self.get_success(lock.__aenter__())

        lock2 = self.get_success(
            self.store.try_acquire_read_write_lock("name1", "key1", write=True)
        )
        self.assertIsNone(lock2)

        lock3 = self.get_success(
            self.store.try_acquire_read_write_lock("name2", "key2", write=False)
        )
        self.assertIsNone(lock3)

        # Overlapping locks attempts will fail, and won't lock any locks.
        lock4 = self.get_success(
            self.store.try_acquire_multi_read_write_lock(
                [("name1", "key1"), ("name3", "key3")], write=True
            )
        )
        self.assertIsNone(lock4)

        lock5 = self.get_success(
            self.store.try_acquire_read_write_lock("name3", "key3", write=True)
        )
        self.assertIsNotNone(lock5)
        assert lock5 is not None
        self.get_success(lock5.__aenter__())
        self.get_success(lock5.__aexit__(None, None, None))

        # Once we release the lock we can take out the locks again.
        self.get_success(lock.__aexit__(None, None, None))

        lock6 = self.get_success(
            self.store.try_acquire_read_write_lock("name1", "key1", write=True)
        )
        self.assertIsNotNone(lock6)
        assert lock6 is not None
        self.get_success(lock6.__aenter__())
        self.get_success(lock6.__aexit__(None, None, None))
