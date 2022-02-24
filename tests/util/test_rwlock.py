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

from typing import AsyncContextManager, Callable, Tuple

from twisted.internet import defer
from twisted.internet.defer import Deferred

from synapse.util.async_helpers import ReadWriteLock

from tests import unittest


class ReadWriteLockTestCase(unittest.TestCase):
    def _assert_called_before_not_after(self, lst, first_false):
        for i, d in enumerate(lst[:first_false]):
            self.assertTrue(d.called, msg="%d was unexpectedly false" % i)

        for i, d in enumerate(lst[first_false:]):
            self.assertFalse(
                d.called, msg="%d was unexpectedly true" % (i + first_false)
            )

    def test_rwlock(self):
        rwlock = ReadWriteLock()
        key = "key"

        def start_reader_or_writer(
            read_or_write: Callable[[str], AsyncContextManager]
        ) -> Tuple["Deferred[None]", "Deferred[None]"]:
            acquired_d: "Deferred[None]" = Deferred()
            release_d: "Deferred[None]" = Deferred()

            async def action():
                async with read_or_write(key):
                    acquired_d.callback(None)
                    await release_d

            defer.ensureDeferred(action())
            return acquired_d, release_d

        ds = [
            start_reader_or_writer(rwlock.read),  # 0
            start_reader_or_writer(rwlock.read),  # 1
            start_reader_or_writer(rwlock.write),  # 2
            start_reader_or_writer(rwlock.write),  # 3
            start_reader_or_writer(rwlock.read),  # 4
            start_reader_or_writer(rwlock.read),  # 5
            start_reader_or_writer(rwlock.write),  # 6
        ]
        # `Deferred`s that resolve when each reader or writer acquires the lock.
        acquired_ds = [acquired_d for acquired_d, _release_d in ds]
        # `Deferred`s that will trigger the release of locks when resolved.
        release_ds = [release_d for _acquired_d, release_d in ds]

        self._assert_called_before_not_after(acquired_ds, 2)

        self._assert_called_before_not_after(acquired_ds, 2)
        release_ds[0].callback(None)
        self._assert_called_before_not_after(acquired_ds, 2)

        self._assert_called_before_not_after(acquired_ds, 2)
        release_ds[1].callback(None)
        self._assert_called_before_not_after(acquired_ds, 3)

        self._assert_called_before_not_after(acquired_ds, 3)
        release_ds[2].callback(None)
        self._assert_called_before_not_after(acquired_ds, 4)

        self._assert_called_before_not_after(acquired_ds, 4)
        release_ds[3].callback(None)
        self._assert_called_before_not_after(acquired_ds, 6)

        self._assert_called_before_not_after(acquired_ds, 6)
        release_ds[5].callback(None)
        self._assert_called_before_not_after(acquired_ds, 6)

        self._assert_called_before_not_after(acquired_ds, 6)
        release_ds[4].callback(None)
        self._assert_called_before_not_after(acquired_ds, 7)

        release_ds[6].callback(None)

        acquired_d, release_d = start_reader_or_writer(rwlock.write)
        self.assertTrue(acquired_d.called)
        release_d.callback(None)

        acquired_d, release_d = start_reader_or_writer(rwlock.read)
        self.assertTrue(acquired_d.called)
        release_d.callback(None)

    def test_lock_handoff_to_nonblocking_writer(self):
        """Test a writer handing the lock to another writer that completes instantly."""
        rwlock = ReadWriteLock()
        key = "key"

        unblock: "Deferred[None]" = Deferred()

        async def blocking_write():
            async with rwlock.write(key):
                await unblock

        async def nonblocking_write():
            async with rwlock.write(key):
                pass

        d1 = defer.ensureDeferred(blocking_write())
        d2 = defer.ensureDeferred(nonblocking_write())
        self.assertFalse(d1.called)
        self.assertFalse(d2.called)

        # Unblock the first writer. The second writer will complete without blocking.
        unblock.callback(None)
        self.assertTrue(d1.called)
        self.assertTrue(d2.called)

        # The `ReadWriteLock` should operate as normal.
        d3 = defer.ensureDeferred(nonblocking_write())
        self.assertTrue(d3.called)
