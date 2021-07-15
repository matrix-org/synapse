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
from types import TracebackType
from typing import TYPE_CHECKING, Dict, Optional, Tuple, Type

from twisted.internet.interfaces import IReactorCore

from synapse.metrics.background_process_metrics import wrap_as_background_process
from synapse.storage._base import SQLBaseStore
from synapse.storage.database import DatabasePool, LoggingTransaction
from synapse.storage.types import Connection
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

    def __init__(self, database: DatabasePool, db_conn: Connection, hs: "HomeServer"):
        super().__init__(database, db_conn, hs)

        self._reactor = hs.get_reactor()
        self._instance_name = hs.get_instance_id()

        # A map from `(lock_name, lock_key)` to the token of any locks that we
        # think we currently hold.
        self._live_tokens: Dict[Tuple[str, str], str] = {}

        # When we shut down we want to remove the locks. Technically this can
        # lead to a race, as we may drop the lock while we are still processing.
        # However, a) it should be a small window, b) the lock is best effort
        # anyway and c) we want to really avoid leaking locks when we restart.
        hs.get_reactor().addSystemEventTrigger(
            "before",
            "shutdown",
            self._on_shutdown,
        )

    @wrap_as_background_process("LockStore._on_shutdown")
    async def _on_shutdown(self) -> None:
        """Called when the server is shutting down"""
        logger.info("Dropping held locks due to shutdown")

        for (lock_name, lock_key), token in self._live_tokens.items():
            await self._drop_lock(lock_name, lock_key, token)

        logger.info("Dropped locks due to shutdown")

    async def try_acquire_lock(self, lock_name: str, lock_key: str) -> Optional["Lock"]:
        """Try to acquire a lock for the given name/key. Will return an async
        context manager if the lock is successfully acquired, which *must* be
        used (otherwise the lock will leak).
        """

        now = self._clock.time_msec()
        token = random_string(6)

        if self.db_pool.engine.can_native_upsert:

            def _try_acquire_lock_txn(txn: LoggingTransaction) -> bool:
                # We take out the lock if either a) there is no row for the lock
                # already or b) the existing row has timed out.
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

        else:
            # If we're on an old SQLite we emulate the above logic by first
            # clearing out any existing stale locks and then upserting.

            def _try_acquire_lock_emulated_txn(txn: LoggingTransaction) -> bool:
                sql = """
                    DELETE FROM worker_locks
                    WHERE
                        lock_name = ?
                        AND lock_key = ?
                        AND last_renewed_ts < ?
                """
                txn.execute(
                    sql,
                    (lock_name, lock_key, now - _LOCK_TIMEOUT_MS),
                )

                inserted = self.db_pool.simple_upsert_txn_emulated(
                    txn,
                    table="worker_locks",
                    keyvalues={
                        "lock_name": lock_name,
                        "lock_key": lock_key,
                    },
                    values={},
                    insertion_values={
                        "token": token,
                        "last_renewed_ts": self._clock.time_msec(),
                        "instance_name": self._instance_name,
                    },
                )

                return inserted

            did_lock = await self.db_pool.runInteraction(
                "try_acquire_lock_emulated", _try_acquire_lock_emulated_txn
            )

            if not did_lock:
                return None

        self._live_tokens[(lock_name, lock_key)] = token

        return Lock(
            self._reactor,
            self._clock,
            self,
            lock_name=lock_name,
            lock_key=lock_key,
            token=token,
        )

    async def _is_lock_still_valid(
        self, lock_name: str, lock_key: str, token: str
    ) -> bool:
        """Checks whether this instance still holds the lock."""
        last_renewed_ts = await self.db_pool.simple_select_one_onecol(
            table="worker_locks",
            keyvalues={
                "lock_name": lock_name,
                "lock_key": lock_key,
                "token": token,
            },
            retcol="last_renewed_ts",
            allow_none=True,
            desc="is_lock_still_valid",
        )
        return (
            last_renewed_ts is not None
            and self._clock.time_msec() - _LOCK_TIMEOUT_MS < last_renewed_ts
        )

    async def _renew_lock(self, lock_name: str, lock_key: str, token: str) -> None:
        """Attempt to renew the lock if we still hold it."""
        await self.db_pool.simple_update(
            table="worker_locks",
            keyvalues={
                "lock_name": lock_name,
                "lock_key": lock_key,
                "token": token,
            },
            updatevalues={"last_renewed_ts": self._clock.time_msec()},
            desc="renew_lock",
        )

    async def _drop_lock(self, lock_name: str, lock_key: str, token: str) -> None:
        """Attempt to drop the lock, if we still hold it"""
        await self.db_pool.simple_delete(
            table="worker_locks",
            keyvalues={
                "lock_name": lock_name,
                "lock_key": lock_key,
                "token": token,
            },
            desc="drop_lock",
        )

        self._live_tokens.pop((lock_name, lock_key), None)


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
        reactor: IReactorCore,
        clock: Clock,
        store: LockStore,
        lock_name: str,
        lock_key: str,
        token: str,
    ) -> None:
        self._reactor = reactor
        self._clock = clock
        self._store = store
        self._lock_name = lock_name
        self._lock_key = lock_key

        self._token = token

        self._looping_call = clock.looping_call(
            self._renew, _RENEWAL_INTERVAL_MS, store, lock_name, lock_key, token
        )

        self._dropped = False

    @staticmethod
    @wrap_as_background_process("Lock._renew")
    async def _renew(
        store: LockStore,
        lock_name: str,
        lock_key: str,
        token: str,
    ) -> None:
        """Renew the lock.

        Note: this is a static method, rather than using self.*, so that we
        don't end up with a reference to `self` in the reactor, which would stop
        this from being cleaned up if we dropped the context manager.
        """
        await store._renew_lock(lock_name, lock_key, token)

    async def is_still_valid(self) -> bool:
        """Check if the lock is still held by us"""
        return await self._store._is_lock_still_valid(
            self._lock_name, self._lock_key, self._token
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

        if self._looping_call.running:
            self._looping_call.stop()

        await self._store._drop_lock(self._lock_name, self._lock_key, self._token)
        self._dropped = True

    def __del__(self) -> None:
        if not self._dropped:
            # We should not be dropped without the lock being released (unless
            # we're shutting down), but if we are then let's at least stop
            # renewing the lock.
            if self._looping_call.running:
                self._looping_call.stop()

            if self._reactor.running:
                logger.error(
                    "Lock for (%s, %s) dropped without being released",
                    self._lock_name,
                    self._lock_key,
                )
