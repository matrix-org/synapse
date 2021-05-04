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
from typing import TYPE_CHECKING, Awaitable, Callable, Dict, Iterable, Optional

from synapse.metrics.background_process_metrics import run_as_background_process
from synapse.storage.types import Connection
from synapse.types import JsonDict
from synapse.util import json_encoder

from . import engines

if TYPE_CHECKING:
    from synapse.server import HomeServer
    from synapse.storage.database import DatabasePool, LoggingTransaction

logger = logging.getLogger(__name__)


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
        if self.avg_duration_ms == 0:
            return 0
        elif self.total_item_count == 0:
            return None
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

    MINIMUM_BACKGROUND_BATCH_SIZE = 100
    DEFAULT_BACKGROUND_BATCH_SIZE = 100
    BACKGROUND_UPDATE_INTERVAL_MS = 1000
    BACKGROUND_UPDATE_DURATION_MS = 100

    def __init__(self, hs: "HomeServer", database: "DatabasePool"):
        self._clock = hs.get_clock()
        self.db_pool = database

        # if a background update is currently running, its name.
        self._current_background_update = None  # type: Optional[str]

        self._background_update_performance = (
            {}
        )  # type: Dict[str, BackgroundUpdatePerformance]
        self._background_update_handlers = (
            {}
        )  # type: Dict[str, Callable[[JsonDict, int], Awaitable[int]]]
        self._all_done = False

    def start_doing_background_updates(self) -> None:
        run_as_background_process("background_updates", self.run_background_updates)

    async def run_background_updates(self, sleep: bool = True) -> None:
        logger.info("Starting background schema updates")
        while True:
            if sleep:
                await self._clock.sleep(self.BACKGROUND_UPDATE_INTERVAL_MS / 1000.0)

            try:
                result = await self.do_next_background_update(
                    self.BACKGROUND_UPDATE_DURATION_MS
                )
            except Exception:
                logger.exception("Error doing update")
            else:
                if result:
                    logger.info(
                        "No more background updates to do."
                        " Unscheduling background update task."
                    )
                    self._all_done = True
                    return None

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

    async def do_next_background_update(self, desired_duration_ms: float) -> bool:
        """Does some amount of work on the next queued background update

        Returns once some amount of work is done.

        Args:
            desired_duration_ms: How long we want to spend updating.
        Returns:
            True if we have finished running all the background updates, otherwise False
        """

        def get_background_updates_txn(txn):
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

        await self._do_background_update(desired_duration_ms)
        return False

    async def _do_background_update(self, desired_duration_ms: float) -> int:
        assert self._current_background_update is not None
        update_name = self._current_background_update
        logger.info("Starting update batch on background update '%s'", update_name)

        update_handler = self._background_update_handlers[update_name]

        performance = self._background_update_performance.get(update_name)

        if performance is None:
            performance = BackgroundUpdatePerformance(update_name)
            self._background_update_performance[update_name] = performance

        items_per_ms = performance.average_items_per_ms()

        if items_per_ms is not None:
            batch_size = int(desired_duration_ms * items_per_ms)
            # Clamp the batch size so that we always make progress
            batch_size = max(batch_size, self.MINIMUM_BACKGROUND_BATCH_SIZE)
        else:
            batch_size = self.DEFAULT_BACKGROUND_BATCH_SIZE

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

        performance.update(items_updated, duration_ms)

        return len(self._background_update_performance)

    def register_background_update_handler(
        self,
        update_name: str,
        update_handler: Callable[[JsonDict, int], Awaitable[int]],
    ):
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
        self._background_update_handlers[update_name] = update_handler

    def register_noop_background_update(self, update_name: str) -> None:
        """Register a noop handler for a background update.

        This is useful when we previously did a background update, but no
        longer wish to do the update. In this case the background update should
        be removed from the schema delta files, but there may still be some
        users who have the background update queued, so this method should
        also be called to clear the update.

        Args:
            update_name: Name of update
        """

        async def noop_update(progress: JsonDict, batch_size: int) -> int:
            await self._end_background_update(update_name)
            return 1

        self.register_background_update_handler(update_name, noop_update)

    def register_background_index_update(
        self,
        update_name: str,
        index_name: str,
        table: str,
        columns: Iterable[str],
        where_clause: Optional[str] = None,
        unique: bool = False,
        psql_only: bool = False,
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

        if isinstance(self.db_pool.engine, engines.PostgresEngine):
            runner = create_index_psql  # type: Optional[Callable[[Connection], None]]
        elif psql_only:
            runner = None
        else:
            runner = create_index_sqlite

        async def updater(progress, batch_size):
            if runner is not None:
                logger.info("Adding index %s to %s", index_name, table)
                await self.db_pool.runWithConnection(runner)
            await self._end_background_update(update_name)
            return 1

        self.register_background_update_handler(update_name, updater)

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
