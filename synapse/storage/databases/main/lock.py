# Copyright 2021 Matrix.org Foundation C.I.C.
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
import logging
from contextlib import AsyncExitStack
from types import TracebackType
from typing import TYPE_CHECKING, Collection, Optional, Set, Tuple, Type
from weakref import WeakValueDictionary

from twisted.internet.task import LoopingCall

from synapse.metrics.background_process_metrics import wrap_as_background_process
from synapse.storage._base import SQLBaseStore
from synapse.storage.database import (
    DatabasePool,
    LoggingDatabaseConnection,
    LoggingTransaction,
)
from synapse.types import ISynapseReactor
from synapse.util import Clock
from synapse.util.stringutils import random_string

if TYPE_CHECKING:
    from synapse.server import HomeServer


logger = logging.getLogger(__name__)


# How often to renew an acquired lock by updating the `last_renewed_ts` time in
# the lock table.
_RENEWAL_INTERVAL_MS = 30 * 1000

# How long before an acquired lock times out.
_LOCK_TIMEOUT_MS = 2 * 60 * 1000


class LockStore(SQLBaseStore):
    """Provides a best effort distributed lock between worker instances.

    Locks are identified by a name and key. A lock is acquired by inserting into
    the `worker_locks` table if a) there is no existing row for the name/key or
    b) the existing row has a `last_renewed_ts` older than `_LOCK_TIMEOUT_MS`.

    When a lock is taken out the instance inserts a random `token`, the instance
    that holds that token holds the lock until it drops (or times out).

    The instance that holds the lock should regularly update the
    `last_renewed_ts` column with the current time.
    """

    def __init__(
        self,
        database: DatabasePool,
        db_conn: LoggingDatabaseConnection,
        hs: "HomeServer",
    ):
        super().__init__(database, db_conn, hs)

        self._reactor = hs.get_reactor()
        self._instance_name = hs.get_instance_id()

        # A map from `(lock_name, lock_key)` to lock that we think we
        # currently hold.
        self._live_lock_tokens: WeakValueDictionary[
            Tuple[str, str], Lock
        ] = WeakValueDictionary()

        # A map from `(lock_name, lock_key, token)` to read/write lock that we
        # think we currently hold. For a given lock_name/lock_key, there can be
        # multiple read locks at a time but only one write lock (no mixing read
        # and write locks at the same time).
        self._live_read_write_lock_tokens: WeakValueDictionary[
            Tuple[str, str, str], Lock
        ] = WeakValueDictionary()

        # When we shut down we want to remove the locks. Technically this can
        # lead to a race, as we may drop the lock while we are still processing.
        # However, a) it should be a small window, b) the lock is best effort
        # anyway and c) we want to really avoid leaking locks when we restart.
        hs.get_reactor().addSystemEventTrigger(
            "before",
            "shutdown",
            self._on_shutdown,
        )

        self._acquiring_locks: Set[Tuple[str, str]] = set()

        self._clock.looping_call(
            self._reap_stale_read_write_locks, _LOCK_TIMEOUT_MS / 10.0
        )

    @wrap_as_background_process("LockStore._on_shutdown")
    async def _on_shutdown(self) -> None:
        """Called when the server is shutting down"""
        logger.info("Dropping held locks due to shutdown")

        # We need to take a copy of the locks as dropping the locks will cause
        # the dictionary to change.
        locks = list(self._live_lock_tokens.values()) + list(
            self._live_read_write_lock_tokens.values()
        )

        for lock in locks:
            await lock.release()

        logger.info("Dropped locks due to shutdown")

    async def try_acquire_lock(self, lock_name: str, lock_key: str) -> Optional["Lock"]:
        """Try to acquire a lock for the given name/key. Will return an async
        context manager if the lock is successfully acquired, which *must* be
        used (otherwise the lock will leak).
        """
        if (lock_name, lock_key) in self._acquiring_locks:
            return None
        try:
            self._acquiring_locks.add((lock_name, lock_key))
            return await self._try_acquire_lock(lock_name, lock_key)
        finally:
            self._acquiring_locks.discard((lock_name, lock_key))

    async def _try_acquire_lock(
        self, lock_name: str, lock_key: str
    ) -> Optional["Lock"]:
        """Try to acquire a lock for the given name/key. Will return an async
        context manager if the lock is successfully acquired, which *must* be
        used (otherwise the lock will leak).
        """

        # Check if this process has taken out a lock and if it's still valid.
        lock = self._live_lock_tokens.get((lock_name, lock_key))
        if lock and await lock.is_still_valid():
            return None

        now = self._clock.time_msec()
        token = random_string(6)

        def _try_acquire_lock_txn(txn: LoggingTransaction) -> bool:
            # We take out the lock if either a) there is no row for the lock
            # already, b) the existing row has timed out, or c) the row is
            # for this instance (which means the process got killed and
            # restarted)
            sql = """
               INSERT INTO worker_locks (lock_name, lock_key, instance_name, token, last_renewed_ts)
               VALUES (?, ?, ?, ?, ?)
               ON CONFLICT (lock_name, lock_key)
               DO UPDATE
                   SET
                       token = EXCLUDED.token,
                       instance_name = EXCLUDED.instance_name,
                       last_renewed_ts = EXCLUDED.last_renewed_ts
                   WHERE
                       worker_locks.last_renewed_ts < ?
                       OR worker_locks.instance_name = EXCLUDED.instance_name
           """
            txn.execute(
                sql,
                (
                    lock_name,
                    lock_key,
                    self._instance_name,
                    token,
                    now,
                    now - _LOCK_TIMEOUT_MS,
                ),
            )

            # We only acquired the lock if we inserted or updated the table.
            return bool(txn.rowcount)

        did_lock = await self.db_pool.runInteraction(
            "try_acquire_lock",
            _try_acquire_lock_txn,
            # We can autocommit here as we're executing a single query, this
            # will avoid serialization errors.
            db_autocommit=True,
        )
        if not did_lock:
            return None

        lock = Lock(
            self._reactor,
            self._clock,
            self,
            read_write=False,
            lock_name=lock_name,
            lock_key=lock_key,
            token=token,
        )

        self._live_lock_tokens[(lock_name, lock_key)] = lock

        return lock

    async def try_acquire_read_write_lock(
        self,
        lock_name: str,
        lock_key: str,
        write: bool,
    ) -> Optional["Lock"]:
        """Try to acquire a lock for the given name/key. Will return an async
        context manager if the lock is successfully acquired, which *must* be
        used (otherwise the lock will leak).
        """

        try:
            lock = await self.db_pool.runInteraction(
                "try_acquire_read_write_lock",
                self._try_acquire_read_write_lock_txn,
                lock_name,
                lock_key,
                write,
                db_autocommit=True,
            )
        except self.database_engine.module.IntegrityError:
            return None

        return lock

    def _try_acquire_read_write_lock_txn(
        self,
        txn: LoggingTransaction,
        lock_name: str,
        lock_key: str,
        write: bool,
    ) -> "Lock":
        # We attempt to acquire the lock by inserting into
        # `worker_read_write_locks` and seeing if that fails any
        # constraints. If it doesn't then we have acquired the lock,
        # otherwise we haven't.

        now = self._clock.time_msec()
        token = random_string(6)

        self.db_pool.simple_insert_txn(
            txn,
            table="worker_read_write_locks",
            values={
                "lock_name": lock_name,
                "lock_key": lock_key,
                "write_lock": write,
                "instance_name": self._instance_name,
                "token": token,
                "last_renewed_ts": now,
            },
        )

        lock = Lock(
            self._reactor,
            self._clock,
            self,
            read_write=True,
            lock_name=lock_name,
            lock_key=lock_key,
            token=token,
        )

        def set_lock() -> None:
            self._live_read_write_lock_tokens[(lock_name, lock_key, token)] = lock

        txn.call_after(set_lock)

        return lock

    async def try_acquire_multi_read_write_lock(
        self,
        lock_names: Collection[Tuple[str, str]],
        write: bool,
    ) -> Optional[AsyncExitStack]:
        """Try to acquire multiple locks for the given names/keys. Will return
        an async context manager if the locks are successfully acquired, which
        *must* be used (otherwise the lock will leak).

        If only a subset of the locks can be acquired then it will immediately
        drop them and return `None`.
        """
        try:
            locks = await self.db_pool.runInteraction(
                "try_acquire_multi_read_write_lock",
                self._try_acquire_multi_read_write_lock_txn,
                lock_names,
                write,
            )
        except self.database_engine.module.IntegrityError:
            return None

        stack = AsyncExitStack()

        for lock in locks:
            await stack.enter_async_context(lock)

        return stack

    def _try_acquire_multi_read_write_lock_txn(
        self,
        txn: LoggingTransaction,
        lock_names: Collection[Tuple[str, str]],
        write: bool,
    ) -> Collection["Lock"]:
        locks = []

        for lock_name, lock_key in lock_names:
            lock = self._try_acquire_read_write_lock_txn(
                txn, lock_name, lock_key, write
            )
            locks.append(lock)

        return locks

    @wrap_as_background_process("_reap_stale_read_write_locks")
    async def _reap_stale_read_write_locks(self) -> None:
        delete_sql = """
            DELETE FROM worker_read_write_locks
                WHERE last_renewed_ts < ?
        """

        def reap_stale_read_write_locks_txn(txn: LoggingTransaction) -> None:
            txn.execute(delete_sql, (self._clock.time_msec() - _LOCK_TIMEOUT_MS,))
            if txn.rowcount:
                logger.info("Reaped %d stale locks", txn.rowcount)

        await self.db_pool.runInteraction(
            "_reap_stale_read_write_locks",
            reap_stale_read_write_locks_txn,
            db_autocommit=True,
        )


class Lock:
    """An async context manager that manages an acquired lock, ensuring it is
    regularly renewed and dropping it when the context manager exits.

    The lock object has an `is_still_valid` method which can be used to
    double-check the lock is still valid, if e.g. processing work in a loop.

    For example:

        lock = await self.store.try_acquire_lock(...)
        if not lock:
            return

        async with lock:
            for item in work:
                await process(item)

                if not await lock.is_still_valid():
                    break
    """

    def __init__(
        self,
        reactor: ISynapseReactor,
        clock: Clock,
        store: LockStore,
        read_write: bool,
        lock_name: str,
        lock_key: str,
        token: str,
    ) -> None:
        self._reactor = reactor
        self._clock = clock
        self._store = store
        self._read_write = read_write
        self._lock_name = lock_name
        self._lock_key = lock_key

        self._token = token

        self._table = "worker_read_write_locks" if read_write else "worker_locks"

        # We might be called from a non-main thread, so we defer setting up the
        # looping call.
        self._looping_call: Optional[LoopingCall] = None
        reactor.callFromThread(self._setup_looping_call)

        self._dropped = False

    def _setup_looping_call(self) -> None:
        self._looping_call = self._clock.looping_call(
            self._renew,
            _RENEWAL_INTERVAL_MS,
            self._store,
            self._clock,
            self._read_write,
            self._lock_name,
            self._lock_key,
            self._token,
        )

    @staticmethod
    @wrap_as_background_process("Lock._renew")
    async def _renew(
        store: LockStore,
        clock: Clock,
        read_write: bool,
        lock_name: str,
        lock_key: str,
        token: str,
    ) -> None:
        """Renew the lock.

        Note: this is a static method, rather than using self.*, so that we
        don't end up with a reference to `self` in the reactor, which would stop
        this from being cleaned up if we dropped the context manager.
        """
        table = "worker_read_write_locks" if read_write else "worker_locks"
        await store.db_pool.simple_update(
            table=table,
            keyvalues={
                "lock_name": lock_name,
                "lock_key": lock_key,
                "token": token,
            },
            updatevalues={"last_renewed_ts": clock.time_msec()},
            desc="renew_lock",
        )

    async def is_still_valid(self) -> bool:
        """Check if the lock is still held by us"""
        last_renewed_ts = await self._store.db_pool.simple_select_one_onecol(
            table=self._table,
            keyvalues={
                "lock_name": self._lock_name,
                "lock_key": self._lock_key,
                "token": self._token,
            },
            retcol="last_renewed_ts",
            allow_none=True,
            desc="is_lock_still_valid",
        )
        return (
            last_renewed_ts is not None
            and self._clock.time_msec() - _LOCK_TIMEOUT_MS < last_renewed_ts
        )

    async def __aenter__(self) -> None:
        if self._dropped:
            raise Exception("Cannot reuse a Lock object")

    async def __aexit__(
        self,
        _exctype: Optional[Type[BaseException]],
        _excinst: Optional[BaseException],
        _exctb: Optional[TracebackType],
    ) -> bool:
        await self.release()

        return False

    async def release(self) -> None:
        """Release the lock.

        This is automatically called when using the lock as a context manager.
        """

        if self._dropped:
            return

        if self._looping_call and self._looping_call.running:
            self._looping_call.stop()

        await self._store.db_pool.simple_delete(
            table=self._table,
            keyvalues={
                "lock_name": self._lock_name,
                "lock_key": self._lock_key,
                "token": self._token,
            },
            desc="drop_lock",
        )

        if self._read_write:
            self._store._live_read_write_lock_tokens.pop(
                (self._lock_name, self._lock_key, self._token), None
            )
        else:
            self._store._live_lock_tokens.pop((self._lock_name, self._lock_key), None)

        self._dropped = True

    def __del__(self) -> None:
        if not self._dropped:
            # We should not be dropped without the lock being released (unless
            # we're shutting down), but if we are then let's at least stop
            # renewing the lock.
            if self._looping_call and self._looping_call.running:
                # We might be called from a non-main thread.
                self._reactor.callFromThread(self._looping_call.stop)

            if self._reactor.running:
                logger.error(
                    "Lock for (%s, %s) dropped without being released",
                    self._lock_name,
                    self._lock_key,
                )
