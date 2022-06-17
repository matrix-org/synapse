# Copyright 2014-2016 OpenMarket Ltd
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
from typing import (
    TYPE_CHECKING,
    Any,
    AsyncContextManager,
    Awaitable,
    Callable,
    Dict,
    Iterable,
    List,
    Optional,
    Type,
)

import attr

from synapse.metrics.background_process_metrics import run_as_background_process
from synapse.storage.types import Connection, Cursor
from synapse.types import JsonDict
from synapse.util import Clock, json_encoder

from . import engines

if TYPE_CHECKING:
    from synapse.server import HomeServer
    from synapse.storage.database import DatabasePool, LoggingTransaction

logger = logging.getLogger(__name__)


ON_UPDATE_CALLBACK = Callable[[str, str, bool], AsyncContextManager[int]]
DEFAULT_BATCH_SIZE_CALLBACK = Callable[[str, str], Awaitable[int]]
MIN_BATCH_SIZE_CALLBACK = Callable[[str, str], Awaitable[int]]


@attr.s(slots=True, frozen=True, auto_attribs=True)
class _BackgroundUpdateHandler:
    """A handler for a given background update.

    Attributes:
        callback: The function to call to make progress on the background
            update.
        oneshot: Wether the update is likely to happen all in one go, ignoring
            the supplied target duration, e.g. index creation. This is used by
            the update controller to help correctly schedule the update.
    """

    callback: Callable[[JsonDict, int], Awaitable[int]]
    oneshot: bool = False


class _BackgroundUpdateContextManager:
    def __init__(
        self, sleep: bool, clock: Clock, sleep_duration_ms: int, update_duration: int
    ):
        self._sleep = sleep
        self._clock = clock
        self._sleep_duration_ms = sleep_duration_ms
        self._update_duration_ms = update_duration

    async def __aenter__(self) -> int:
        if self._sleep:
            await self._clock.sleep(self._sleep_duration_ms / 1000)

        return self._update_duration_ms

    async def __aexit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc: Optional[BaseException],
        tb: Optional[TracebackType],
    ) -> None:
        pass


class BackgroundUpdatePerformance:
    """Tracks the how long a background update is taking to update its items"""

    def __init__(self, name: str):
        self.name = name
        self.total_item_count = 0
        self.total_duration_ms = 0.0
        self.avg_item_count = 0.0
        self.avg_duration_ms = 0.0

    def update(self, item_count: int, duration_ms: float) -> None:
        """Update the stats after doing an update"""
        self.total_item_count += item_count
        self.total_duration_ms += duration_ms

        # Exponential moving averages for the number of items updated and
        # the duration.
        self.avg_item_count += 0.1 * (item_count - self.avg_item_count)
        self.avg_duration_ms += 0.1 * (duration_ms - self.avg_duration_ms)

    def average_items_per_ms(self) -> Optional[float]:
        """An estimate of how long it takes to do a single update.
        Returns:
            A duration in ms as a float
        """
        # We want to return None if this is the first background update item
        if self.total_item_count == 0:
            return None
        # Avoid dividing by zero
        elif self.avg_duration_ms == 0:
            return 0
        else:
            # Use the exponential moving average so that we can adapt to
            # changes in how long the update process takes.
            return float(self.avg_item_count) / float(self.avg_duration_ms)

    def total_items_per_ms(self) -> Optional[float]:
        """An estimate of how long it takes to do a single update.
        Returns:
            A duration in ms as a float
        """
        if self.total_duration_ms == 0:
            return 0
        elif self.total_item_count == 0:
            return None
        else:
            return float(self.total_item_count) / float(self.total_duration_ms)


class BackgroundUpdater:
    """Background updates are updates to the database that run in the
    background. Each update processes a batch of data at once. We attempt to
    limit the impact of each update by monitoring how long each batch takes to
    process and autotuning the batch size.
    """

    def __init__(self, hs: "HomeServer", database: "DatabasePool"):
        self._clock = hs.get_clock()
        self.db_pool = database

        self._database_name = database.name()

        # if a background update is currently running, its name.
        self._current_background_update: Optional[str] = None

        self._on_update_callback: Optional[ON_UPDATE_CALLBACK] = None
        self._default_batch_size_callback: Optional[DEFAULT_BATCH_SIZE_CALLBACK] = None
        self._min_batch_size_callback: Optional[MIN_BATCH_SIZE_CALLBACK] = None

        self._background_update_performance: Dict[str, BackgroundUpdatePerformance] = {}
        self._background_update_handlers: Dict[str, _BackgroundUpdateHandler] = {}
        self._all_done = False

        # Whether we're currently running updates
        self._running = False

        # Whether background updates are enabled. This allows us to
        # enable/disable background updates via the admin API.
        self.enabled = True

        self.minimum_background_batch_size = hs.config.background_updates.min_batch_size
        self.default_background_batch_size = (
            hs.config.background_updates.default_batch_size
        )
        self.update_duration_ms = hs.config.background_updates.update_duration_ms
        self.sleep_duration_ms = hs.config.background_updates.sleep_duration_ms
        self.sleep_enabled = hs.config.background_updates.sleep_enabled

    def register_update_controller_callbacks(
        self,
        on_update: ON_UPDATE_CALLBACK,
        default_batch_size: Optional[DEFAULT_BATCH_SIZE_CALLBACK] = None,
        min_batch_size: Optional[DEFAULT_BATCH_SIZE_CALLBACK] = None,
    ) -> None:
        """Register callbacks from a module for each hook."""
        if self._on_update_callback is not None:
            logger.warning(
                "More than one module tried to register callbacks for controlling"
                " background updates. Only the callbacks registered by the first module"
                " (in order of appearance in Synapse's configuration file) that tried to"
                " do so will be called."
            )

            return

        self._on_update_callback = on_update

        if default_batch_size is not None:
            self._default_batch_size_callback = default_batch_size

        if min_batch_size is not None:
            self._min_batch_size_callback = min_batch_size

    def _get_context_manager_for_update(
        self,
        sleep: bool,
        update_name: str,
        database_name: str,
        oneshot: bool,
    ) -> AsyncContextManager[int]:
        """Get a context manager to run a background update with.

        If a module has registered a `update_handler` callback, use the context manager
        it returns.

        Otherwise, returns a context manager that will return a default value, optionally
        sleeping if needed.

        Args:
            sleep: Whether we can sleep between updates.
            update_name: The name of the update.
            database_name: The name of the database the update is being run on.
            oneshot: Whether the update will complete all in one go, e.g. index creation.
                In such cases the returned target duration is ignored.

        Returns:
            The target duration in milliseconds that the background update should run for.

            Note: this is a *target*, and an iteration may take substantially longer or
            shorter.
        """
        if self._on_update_callback is not None:
            return self._on_update_callback(update_name, database_name, oneshot)

        return _BackgroundUpdateContextManager(
            sleep, self._clock, self.sleep_duration_ms, self.update_duration_ms
        )

    async def _default_batch_size(self, update_name: str, database_name: str) -> int:
        """The batch size to use for the first iteration of a new background
        update.
        """
        if self._default_batch_size_callback is not None:
            return await self._default_batch_size_callback(update_name, database_name)

        return self.default_background_batch_size

    async def _min_batch_size(self, update_name: str, database_name: str) -> int:
        """A lower bound on the batch size of a new background update.

        Used to ensure that progress is always made. Must be greater than 0.
        """
        if self._min_batch_size_callback is not None:
            return await self._min_batch_size_callback(update_name, database_name)

        return self.minimum_background_batch_size

    def get_current_update(self) -> Optional[BackgroundUpdatePerformance]:
        """Returns the current background update, if any."""

        update_name = self._current_background_update
        if not update_name:
            return None

        perf = self._background_update_performance.get(update_name)
        if not perf:
            perf = BackgroundUpdatePerformance(update_name)

        return perf

    def start_doing_background_updates(self) -> None:
        if self.enabled:
            # if we start a new background update, not all updates are done.
            self._all_done = False
            sleep = self.sleep_enabled
            run_as_background_process(
                "background_updates", self.run_background_updates, sleep
            )

    async def run_background_updates(self, sleep: bool) -> None:
        if self._running or not self.enabled:
            return

        self._running = True

        back_to_back_failures = 0

        try:
            logger.info("Starting background schema updates")
            while self.enabled:
                try:
                    result = await self.do_next_background_update(sleep)
                    back_to_back_failures = 0
                except Exception:
                    back_to_back_failures += 1
                    if back_to_back_failures >= 5:
                        raise RuntimeError(
                            "5 back-to-back background update failures; aborting."
                        )
                    logger.exception("Error doing update")
                else:
                    if result:
                        logger.info(
                            "No more background updates to do."
                            " Unscheduling background update task."
                        )
                        self._all_done = True
                        return None
        finally:
            self._running = False

    async def has_completed_background_updates(self) -> bool:
        """Check if all the background updates have completed

        Returns:
            True if all background updates have completed
        """
        # if we've previously determined that there is nothing left to do, that
        # is easy
        if self._all_done:
            return True

        # obviously, if we are currently processing an update, we're not done.
        if self._current_background_update:
            return False

        # otherwise, check if there are updates to be run. This is important,
        # as we may be running on a worker which doesn't perform the bg updates
        # itself, but still wants to wait for them to happen.
        updates = await self.db_pool.simple_select_onecol(
            "background_updates",
            keyvalues=None,
            retcol="1",
            desc="has_completed_background_updates",
        )
        if not updates:
            self._all_done = True
            return True

        return False

    async def has_completed_background_update(self, update_name: str) -> bool:
        """Check if the given background update has finished running."""
        if self._all_done:
            return True

        if update_name == self._current_background_update:
            return False

        update_exists = await self.db_pool.simple_select_one_onecol(
            "background_updates",
            keyvalues={"update_name": update_name},
            retcol="1",
            desc="has_completed_background_update",
            allow_none=True,
        )

        return not update_exists

    async def do_next_background_update(self, sleep: bool = True) -> bool:
        """Does some amount of work on the next queued background update

        Returns once some amount of work is done.

        Args:
            sleep: Whether to limit how quickly we run background updates or
                not.

        Returns:
            True if we have finished running all the background updates, otherwise False
        """

        def get_background_updates_txn(txn: Cursor) -> List[Dict[str, Any]]:
            txn.execute(
                """
                SELECT update_name, depends_on FROM background_updates
                ORDER BY ordering, update_name
                """
            )
            return self.db_pool.cursor_to_dict(txn)

        if not self._current_background_update:
            all_pending_updates = await self.db_pool.runInteraction(
                "background_updates",
                get_background_updates_txn,
            )
            if not all_pending_updates:
                # no work left to do
                return True

            # find the first update which isn't dependent on another one in the queue.
            pending = {update["update_name"] for update in all_pending_updates}
            for upd in all_pending_updates:
                depends_on = upd["depends_on"]
                if not depends_on or depends_on not in pending:
                    break
                logger.info(
                    "Not starting on bg update %s until %s is done",
                    upd["update_name"],
                    depends_on,
                )
            else:
                # if we get to the end of that for loop, there is a problem
                raise Exception(
                    "Unable to find a background update which doesn't depend on "
                    "another: dependency cycle?"
                )

            self._current_background_update = upd["update_name"]

        # We have a background update to run, otherwise we would have returned
        # early.
        assert self._current_background_update is not None
        update_info = self._background_update_handlers[self._current_background_update]

        async with self._get_context_manager_for_update(
            sleep=sleep,
            update_name=self._current_background_update,
            database_name=self._database_name,
            oneshot=update_info.oneshot,
        ) as desired_duration_ms:
            await self._do_background_update(desired_duration_ms)

        return False

    async def _do_background_update(self, desired_duration_ms: float) -> int:
        assert self._current_background_update is not None
        update_name = self._current_background_update
        logger.info("Starting update batch on background update '%s'", update_name)

        update_handler = self._background_update_handlers[update_name].callback

        performance = self._background_update_performance.get(update_name)

        if performance is None:
            performance = BackgroundUpdatePerformance(update_name)
            self._background_update_performance[update_name] = performance

        items_per_ms = performance.average_items_per_ms()

        if items_per_ms is not None:
            batch_size = int(desired_duration_ms * items_per_ms)
            # Clamp the batch size so that we always make progress
            batch_size = max(
                batch_size,
                await self._min_batch_size(update_name, self._database_name),
            )
        else:
            batch_size = await self._default_batch_size(
                update_name, self._database_name
            )

        progress_json = await self.db_pool.simple_select_one_onecol(
            "background_updates",
            keyvalues={"update_name": update_name},
            retcol="progress_json",
        )

        # Avoid a circular import.
        from synapse.storage._base import db_to_json

        progress = db_to_json(progress_json)

        time_start = self._clock.time_msec()
        items_updated = await update_handler(progress, batch_size)
        time_stop = self._clock.time_msec()

        duration_ms = time_stop - time_start

        performance.update(items_updated, duration_ms)

        logger.info(
            "Running background update %r. Processed %r items in %rms."
            " (total_rate=%r/ms, current_rate=%r/ms, total_updated=%r, batch_size=%r)",
            update_name,
            items_updated,
            duration_ms,
            performance.total_items_per_ms(),
            performance.average_items_per_ms(),
            performance.total_item_count,
            batch_size,
        )

        return len(self._background_update_performance)

    def register_background_update_handler(
        self,
        update_name: str,
        update_handler: Callable[[JsonDict, int], Awaitable[int]],
    ) -> None:
        """Register a handler for doing a background update.

        The handler should take two arguments:

        * A dict of the current progress
        * An integer count of the number of items to update in this batch.

        The handler should return a deferred or coroutine which returns an integer count
        of items updated.

        The handler is responsible for updating the progress of the update.

        Args:
            update_name: The name of the update that this code handles.
            update_handler: The function that does the update.
        """
        self._background_update_handlers[update_name] = _BackgroundUpdateHandler(
            update_handler
        )

    def register_background_index_update(
        self,
        update_name: str,
        index_name: str,
        table: str,
        columns: Iterable[str],
        where_clause: Optional[str] = None,
        unique: bool = False,
        psql_only: bool = False,
        replaces_index: Optional[str] = None,
    ) -> None:
        """Helper for store classes to do a background index addition

        To use:

        1. use a schema delta file to add a background update. Example:
            INSERT INTO background_updates (update_name, progress_json) VALUES
                ('my_new_index', '{}');

        2. In the Store constructor, call this method

        Args:
            update_name: update_name to register for
            index_name: name of index to add
            table: table to add index to
            columns: columns/expressions to include in index
            unique: true to make a UNIQUE index
            psql_only: true to only create this index on psql databases (useful
                for virtual sqlite tables)
            replaces_index: The name of an index that this index replaces.
                The named index will be dropped upon completion of the new index.
        """

        def create_index_psql(conn: Connection) -> None:
            conn.rollback()
            # postgres insists on autocommit for the index
            conn.set_session(autocommit=True)  # type: ignore

            try:
                c = conn.cursor()

                # If a previous attempt to create the index was interrupted,
                # we may already have a half-built index. Let's just drop it
                # before trying to create it again.

                sql = "DROP INDEX IF EXISTS %s" % (index_name,)
                logger.debug("[SQL] %s", sql)
                c.execute(sql)

                sql = (
                    "CREATE %(unique)s INDEX CONCURRENTLY %(name)s"
                    " ON %(table)s"
                    " (%(columns)s) %(where_clause)s"
                ) % {
                    "unique": "UNIQUE" if unique else "",
                    "name": index_name,
                    "table": table,
                    "columns": ", ".join(columns),
                    "where_clause": "WHERE " + where_clause if where_clause else "",
                }
                logger.debug("[SQL] %s", sql)
                c.execute(sql)

                if replaces_index is not None:
                    # We drop the old index as the new index has now been created.
                    sql = f"DROP INDEX IF EXISTS {replaces_index}"
                    logger.debug("[SQL] %s", sql)
                    c.execute(sql)
            finally:
                conn.set_session(autocommit=False)  # type: ignore

        def create_index_sqlite(conn: Connection) -> None:
            # Sqlite doesn't support concurrent creation of indexes.
            #
            # We don't use partial indices on SQLite as it wasn't introduced
            # until 3.8, and wheezy and CentOS 7 have 3.7
            #
            # We assume that sqlite doesn't give us invalid indices; however
            # we may still end up with the index existing but the
            # background_updates not having been recorded if synapse got shut
            # down at the wrong moment - hance we use IF NOT EXISTS. (SQLite
            # has supported CREATE TABLE|INDEX IF NOT EXISTS since 3.3.0.)
            sql = (
                "CREATE %(unique)s INDEX IF NOT EXISTS %(name)s ON %(table)s"
                " (%(columns)s)"
            ) % {
                "unique": "UNIQUE" if unique else "",
                "name": index_name,
                "table": table,
                "columns": ", ".join(columns),
            }

            c = conn.cursor()
            logger.debug("[SQL] %s", sql)
            c.execute(sql)

            if replaces_index is not None:
                # We drop the old index as the new index has now been created.
                sql = f"DROP INDEX IF EXISTS {replaces_index}"
                logger.debug("[SQL] %s", sql)
                c.execute(sql)

        if isinstance(self.db_pool.engine, engines.PostgresEngine):
            runner: Optional[Callable[[Connection], None]] = create_index_psql
        elif psql_only:
            runner = None
        else:
            runner = create_index_sqlite

        async def updater(progress: JsonDict, batch_size: int) -> int:
            if runner is not None:
                logger.info("Adding index %s to %s", index_name, table)
                await self.db_pool.runWithConnection(runner)
            await self._end_background_update(update_name)
            return 1

        self._background_update_handlers[update_name] = _BackgroundUpdateHandler(
            updater, oneshot=True
        )

    async def _end_background_update(self, update_name: str) -> None:
        """Removes a completed background update task from the queue.

        Args:
            update_name:: The name of the completed task to remove

        Returns:
            None, completes once the task is removed.
        """
        if update_name != self._current_background_update:
            raise Exception(
                "Cannot end background update %s which isn't currently running"
                % update_name
            )
        self._current_background_update = None
        await self.db_pool.simple_delete_one(
            "background_updates", keyvalues={"update_name": update_name}
        )

    async def _background_update_progress(
        self, update_name: str, progress: dict
    ) -> None:
        """Update the progress of a background update

        Args:
            update_name: The name of the background update task
            progress: The progress of the update.
        """

        await self.db_pool.runInteraction(
            "background_update_progress",
            self._background_update_progress_txn,
            update_name,
            progress,
        )

    def _background_update_progress_txn(
        self, txn: "LoggingTransaction", update_name: str, progress: JsonDict
    ) -> None:
        """Update the progress of a background update

        Args:
            txn: The transaction.
            update_name: The name of the background update task
            progress: The progress of the update.
        """

        progress_json = json_encoder.encode(progress)

        self.db_pool.simple_update_one_txn(
            txn,
            "background_updates",
            keyvalues={"update_name": update_name},
            updatevalues={"progress_json": progress_json},
        )
