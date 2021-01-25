# -*- coding: utf-8 -*-
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
import heapq
import logging
import threading
from collections import deque
from contextlib import contextmanager
from typing import Dict, List, Optional, Set, Tuple, Union

import attr
from typing_extensions import Deque

from synapse.metrics.background_process_metrics import run_as_background_process
from synapse.storage.database import DatabasePool, LoggingTransaction
from synapse.storage.types import Cursor
from synapse.storage.util.sequence import PostgresSequenceGenerator

logger = logging.getLogger(__name__)


class IdGenerator:
    def __init__(self, db_conn, table, column):
        self._lock = threading.Lock()
        self._next_id = _load_current_id(db_conn, table, column)

    def get_next(self):
        with self._lock:
            self._next_id += 1
            return self._next_id


def _load_current_id(db_conn, table, column, step=1):
    """

    Args:
        db_conn (object):
        table (str):
        column (str):
        step (int):

    Returns:
        int
    """
    # debug logging for https://github.com/matrix-org/synapse/issues/7968
    logger.info("initialising stream generator for %s(%s)", table, column)
    cur = db_conn.cursor(txn_name="_load_current_id")
    if step == 1:
        cur.execute("SELECT MAX(%s) FROM %s" % (column, table))
    else:
        cur.execute("SELECT MIN(%s) FROM %s" % (column, table))
    (val,) = cur.fetchone()
    cur.close()
    current_id = int(val) if val else step
    return (max if step > 0 else min)(current_id, step)


class StreamIdGenerator:
    """Used to generate new stream ids when persisting events while keeping
    track of which transactions have been completed.

    This allows us to get the "current" stream id, i.e. the stream id such that
    all ids less than or equal to it have completed. This handles the fact that
    persistence of events can complete out of order.

    Args:
        db_conn(connection):  A database connection to use to fetch the
            initial value of the generator from.
        table(str): A database table to read the initial value of the id
            generator from.
        column(str): The column of the database table to read the initial
            value from the id generator from.
        extra_tables(list): List of pairs of database tables and columns to
            use to source the initial value of the generator from. The value
            with the largest magnitude is used.
        step(int): which direction the stream ids grow in. +1 to grow
            upwards, -1 to grow downwards.

    Usage:
        async with stream_id_gen.get_next() as stream_id:
            # ... persist event ...
    """

    def __init__(self, db_conn, table, column, extra_tables=[], step=1):
        assert step != 0
        self._lock = threading.Lock()
        self._step = step
        self._current = _load_current_id(db_conn, table, column, step)
        for table, column in extra_tables:
            self._current = (max if step > 0 else min)(
                self._current, _load_current_id(db_conn, table, column, step)
            )
        self._unfinished_ids = deque()  # type: Deque[int]

    def get_next(self):
        """
        Usage:
            async with stream_id_gen.get_next() as stream_id:
                # ... persist event ...
        """
        with self._lock:
            self._current += self._step
            next_id = self._current

            self._unfinished_ids.append(next_id)

        @contextmanager
        def manager():
            try:
                yield next_id
            finally:
                with self._lock:
                    self._unfinished_ids.remove(next_id)

        return _AsyncCtxManagerWrapper(manager())

    def get_next_mult(self, n):
        """
        Usage:
            async with stream_id_gen.get_next(n) as stream_ids:
                # ... persist events ...
        """
        with self._lock:
            next_ids = range(
                self._current + self._step,
                self._current + self._step * (n + 1),
                self._step,
            )
            self._current += n * self._step

            for next_id in next_ids:
                self._unfinished_ids.append(next_id)

        @contextmanager
        def manager():
            try:
                yield next_ids
            finally:
                with self._lock:
                    for next_id in next_ids:
                        self._unfinished_ids.remove(next_id)

        return _AsyncCtxManagerWrapper(manager())

    def get_current_token(self) -> int:
        """Returns the maximum stream id such that all stream ids less than or
        equal to it have been successfully persisted.

        Returns:
            The maximum stream id.
        """
        with self._lock:
            if self._unfinished_ids:
                return self._unfinished_ids[0] - self._step

            return self._current

    def get_current_token_for_writer(self, instance_name: str) -> int:
        """Returns the position of the given writer.

        For streams with single writers this is equivalent to
        `get_current_token`.
        """
        return self.get_current_token()


class MultiWriterIdGenerator:
    """An ID generator that tracks a stream that can have multiple writers.

    Uses a Postgres sequence to coordinate ID assignment, but positions of other
    writers will only get updated when `advance` is called (by replication).

    Note: Only works with Postgres.

    Args:
        db_conn
        db
        stream_name: A name for the stream, for use in the `stream_positions`
            table. (Does not need to be the same as the replication stream name)
        instance_name: The name of this instance.
        tables: List of tables associated with the stream. Tuple of table
            name, column name that stores the writer's instance name, and
            column name that stores the stream ID.
        sequence_name: The name of the postgres sequence used to generate new
            IDs.
        writers: A list of known writers to use to populate current positions
            on startup. Can be empty if nothing uses `get_current_token` or
            `get_positions` (e.g. caches stream).
        positive: Whether the IDs are positive (true) or negative (false).
            When using negative IDs we go backwards from -1 to -2, -3, etc.
    """

    def __init__(
        self,
        db_conn,
        db: DatabasePool,
        stream_name: str,
        instance_name: str,
        tables: List[Tuple[str, str, str]],
        sequence_name: str,
        writers: List[str],
        positive: bool = True,
    ):
        self._db = db
        self._stream_name = stream_name
        self._instance_name = instance_name
        self._positive = positive
        self._writers = writers
        self._return_factor = 1 if positive else -1

        # We lock as some functions may be called from DB threads.
        self._lock = threading.Lock()

        # Note: If we are a negative stream then we still store all the IDs as
        # positive to make life easier for us, and simply negate the IDs when we
        # return them.
        self._current_positions = {}  # type: Dict[str, int]

        # Set of local IDs that we're still processing. The current position
        # should be less than the minimum of this set (if not empty).
        self._unfinished_ids = set()  # type: Set[int]

        # Set of local IDs that we've processed that are larger than the current
        # position, due to there being smaller unpersisted IDs.
        self._finished_ids = set()  # type: Set[int]

        # We track the max position where we know everything before has been
        # persisted. This is done by a) looking at the min across all instances
        # and b) noting that if we have seen a run of persisted positions
        # without gaps (e.g. 5, 6, 7) then we can skip forward (e.g. to 7).
        #
        # Note: There is no guarentee that the IDs generated by the sequence
        # will be gapless; gaps can form when e.g. a transaction was rolled
        # back. This means that sometimes we won't be able to skip forward the
        # position even though everything has been persisted. However, since
        # gaps should be relatively rare it's still worth doing the book keeping
        # that allows us to skip forwards when there are gapless runs of
        # positions.
        #
        # We start at 1 here as a) the first generated stream ID will be 2, and
        # b) other parts of the code assume that stream IDs are strictly greater
        # than 0.
        self._persisted_upto_position = (
            min(self._current_positions.values()) if self._current_positions else 1
        )
        self._known_persisted_positions = []  # type: List[int]

        self._sequence_gen = PostgresSequenceGenerator(sequence_name)

        # We check that the table and sequence haven't diverged.
        for table, _, id_column in tables:
            self._sequence_gen.check_consistency(
                db_conn,
                table=table,
                id_column=id_column,
                stream_name=stream_name,
                positive=positive,
            )

        # This goes and fills out the above state from the database.
        self._load_current_ids(db_conn, tables)

    def _load_current_ids(
        self, db_conn, tables: List[Tuple[str, str, str]],
    ):
        cur = db_conn.cursor(txn_name="_load_current_ids")

        # Load the current positions of all writers for the stream.
        if self._writers:
            # We delete any stale entries in the positions table. This is
            # important if we add back a writer after a long time; we want to
            # consider that a "new" writer, rather than using the old stale
            # entry here.
            sql = """
                DELETE FROM stream_positions
                WHERE
                    stream_name = ?
                    AND instance_name != ALL(?)
            """
            cur.execute(sql, (self._stream_name, self._writers))

            sql = """
                SELECT instance_name, stream_id FROM stream_positions
                WHERE stream_name = ?
            """
            cur.execute(sql, (self._stream_name,))

            self._current_positions = {
                instance: stream_id * self._return_factor
                for instance, stream_id in cur
                if instance in self._writers
            }

        # We set the `_persisted_upto_position` to be the minimum of all current
        # positions. If empty we use the max stream ID from the DB table.
        min_stream_id = min(self._current_positions.values(), default=None)

        if min_stream_id is None:
            # We add a GREATEST here to ensure that the result is always
            # positive. (This can be a problem for e.g. backfill streams where
            # the server has never backfilled).
            max_stream_id = 1
            for table, _, id_column in tables:
                sql = """
                    SELECT GREATEST(COALESCE(%(agg)s(%(id)s), 1), 1)
                    FROM %(table)s
                """ % {
                    "id": id_column,
                    "table": table,
                    "agg": "MAX" if self._positive else "-MIN",
                }
                cur.execute(sql)
                (stream_id,) = cur.fetchone()

                max_stream_id = max(max_stream_id, stream_id)

            self._persisted_upto_position = max_stream_id
        else:
            # If we have a min_stream_id then we pull out everything greater
            # than it from the DB so that we can prefill
            # `_known_persisted_positions` and get a more accurate
            # `_persisted_upto_position`.
            #
            # We also check if any of the later rows are from this instance, in
            # which case we use that for this instance's current position. This
            # is to handle the case where we didn't finish persisting to the
            # stream positions table before restart (or the stream position
            # table otherwise got out of date).

            self._persisted_upto_position = min_stream_id

            rows = []
            for table, instance_column, id_column in tables:
                sql = """
                    SELECT %(instance)s, %(id)s FROM %(table)s
                    WHERE ? %(cmp)s %(id)s
                """ % {
                    "id": id_column,
                    "table": table,
                    "instance": instance_column,
                    "cmp": "<=" if self._positive else ">=",
                }
                cur.execute(sql, (min_stream_id * self._return_factor,))

                rows.extend(cur)

            # Sort so that we handle rows in order for each instance.
            rows.sort()

            with self._lock:
                for (instance, stream_id,) in rows:
                    stream_id = self._return_factor * stream_id
                    self._add_persisted_position(stream_id)

                    if instance == self._instance_name:
                        self._current_positions[instance] = stream_id

        cur.close()

    def _load_next_id_txn(self, txn) -> int:
        return self._sequence_gen.get_next_id_txn(txn)

    def _load_next_mult_id_txn(self, txn, n: int) -> List[int]:
        return self._sequence_gen.get_next_mult_txn(txn, n)

    def get_next(self):
        """
        Usage:
            async with stream_id_gen.get_next() as stream_id:
                # ... persist event ...
        """

        return _MultiWriterCtxManager(self)

    def get_next_mult(self, n: int):
        """
        Usage:
            async with stream_id_gen.get_next_mult(5) as stream_ids:
                # ... persist events ...
        """

        return _MultiWriterCtxManager(self, n)

    def get_next_txn(self, txn: LoggingTransaction):
        """
        Usage:

            stream_id = stream_id_gen.get_next(txn)
            # ... persist event ...
        """

        next_id = self._load_next_id_txn(txn)

        with self._lock:
            self._unfinished_ids.add(next_id)

        txn.call_after(self._mark_id_as_finished, next_id)
        txn.call_on_exception(self._mark_id_as_finished, next_id)

        # Update the `stream_positions` table with newly updated stream
        # ID (unless self._writers is not set in which case we don't
        # bother, as nothing will read it).
        #
        # We only do this on the success path so that the persisted current
        # position points to a persited row with the correct instance name.
        if self._writers:
            txn.call_after(
                run_as_background_process,
                "MultiWriterIdGenerator._update_table",
                self._db.runInteraction,
                "MultiWriterIdGenerator._update_table",
                self._update_stream_positions_table_txn,
            )

        return self._return_factor * next_id

    def _mark_id_as_finished(self, next_id: int):
        """The ID has finished being processed so we should advance the
        current position if possible.
        """

        with self._lock:
            self._unfinished_ids.discard(next_id)
            self._finished_ids.add(next_id)

            new_cur = None  # type: Optional[int]

            if self._unfinished_ids:
                # If there are unfinished IDs then the new position will be the
                # largest finished ID less than the minimum unfinished ID.

                finished = set()

                min_unfinshed = min(self._unfinished_ids)
                for s in self._finished_ids:
                    if s < min_unfinshed:
                        if new_cur is None or new_cur < s:
                            new_cur = s
                    else:
                        finished.add(s)

                # We clear these out since they're now all less than the new
                # position.
                self._finished_ids = finished
            else:
                # There are no unfinished IDs so the new position is simply the
                # largest finished one.
                new_cur = max(self._finished_ids)

                # We clear these out since they're now all less than the new
                # position.
                self._finished_ids.clear()

            if new_cur:
                curr = self._current_positions.get(self._instance_name, 0)
                self._current_positions[self._instance_name] = max(curr, new_cur)

            self._add_persisted_position(next_id)

    def get_current_token(self) -> int:
        """Returns the maximum stream id such that all stream ids less than or
        equal to it have been successfully persisted.
        """

        return self.get_persisted_upto_position()

    def get_current_token_for_writer(self, instance_name: str) -> int:
        """Returns the position of the given writer.
        """

        # If we don't have an entry for the given instance name, we assume it's a
        # new writer.
        #
        # For new writers we assume their initial position to be the current
        # persisted up to position. This stops Synapse from doing a full table
        # scan when a new writer announces itself over replication.
        with self._lock:
            return self._return_factor * self._current_positions.get(
                instance_name, self._persisted_upto_position
            )

    def get_positions(self) -> Dict[str, int]:
        """Get a copy of the current positon map.

        Note that this won't necessarily include all configured writers if some
        writers haven't written anything yet.
        """

        with self._lock:
            return {
                name: self._return_factor * i
                for name, i in self._current_positions.items()
            }

    def advance(self, instance_name: str, new_id: int):
        """Advance the postion of the named writer to the given ID, if greater
        than existing entry.
        """

        new_id *= self._return_factor

        with self._lock:
            self._current_positions[instance_name] = max(
                new_id, self._current_positions.get(instance_name, 0)
            )

            self._add_persisted_position(new_id)

    def get_persisted_upto_position(self) -> int:
        """Get the max position where all previous positions have been
        persisted.

        Note: In the worst case scenario this will be equal to the minimum
        position across writers. This means that the returned position here can
        lag if one writer doesn't write very often.
        """

        with self._lock:
            return self._return_factor * self._persisted_upto_position

    def _add_persisted_position(self, new_id: int):
        """Record that we have persisted a position.

        This is used to keep the `_current_positions` up to date.
        """

        # We require that the lock is locked by caller
        assert self._lock.locked()

        heapq.heappush(self._known_persisted_positions, new_id)

        # If we're a writer and we don't have any active writes we update our
        # current position to the latest position seen. This allows the instance
        # to report a recent position when asked, rather than a potentially old
        # one (if this instance hasn't written anything for a while).
        our_current_position = self._current_positions.get(self._instance_name)
        if our_current_position and not self._unfinished_ids:
            self._current_positions[self._instance_name] = max(
                our_current_position, new_id
            )

        # We move the current min position up if the minimum current positions
        # of all instances is higher (since by definition all positions less
        # that that have been persisted).
        min_curr = min(self._current_positions.values(), default=0)
        self._persisted_upto_position = max(min_curr, self._persisted_upto_position)

        # We now iterate through the seen positions, discarding those that are
        # less than the current min positions, and incrementing the min position
        # if its exactly one greater.
        #
        # This is also where we discard items from `_known_persisted_positions`
        # (to ensure the list doesn't infinitely grow).
        while self._known_persisted_positions:
            if self._known_persisted_positions[0] <= self._persisted_upto_position:
                heapq.heappop(self._known_persisted_positions)
            elif (
                self._known_persisted_positions[0] == self._persisted_upto_position + 1
            ):
                heapq.heappop(self._known_persisted_positions)
                self._persisted_upto_position += 1
            else:
                # There was a gap in seen positions, so there is nothing more to
                # do.
                break

    def _update_stream_positions_table_txn(self, txn: Cursor):
        """Update the `stream_positions` table with newly persisted position.
        """

        if not self._writers:
            return

        # We upsert the value, ensuring on conflict that we always increase the
        # value (or decrease if stream goes backwards).
        sql = """
            INSERT INTO stream_positions (stream_name, instance_name, stream_id)
            VALUES (?, ?, ?)
            ON CONFLICT (stream_name, instance_name)
            DO UPDATE SET
                stream_id = %(agg)s(stream_positions.stream_id, EXCLUDED.stream_id)
        """ % {
            "agg": "GREATEST" if self._positive else "LEAST",
        }

        pos = (self.get_current_token_for_writer(self._instance_name),)
        txn.execute(sql, (self._stream_name, self._instance_name, pos))


@attr.s(slots=True)
class _AsyncCtxManagerWrapper:
    """Helper class to convert a plain context manager to an async one.

    This is mainly useful if you have a plain context manager but the interface
    requires an async one.
    """

    inner = attr.ib()

    async def __aenter__(self):
        return self.inner.__enter__()

    async def __aexit__(self, exc_type, exc, tb):
        return self.inner.__exit__(exc_type, exc, tb)


@attr.s(slots=True)
class _MultiWriterCtxManager:
    """Async context manager returned by MultiWriterIdGenerator
    """

    id_gen = attr.ib(type=MultiWriterIdGenerator)
    multiple_ids = attr.ib(type=Optional[int], default=None)
    stream_ids = attr.ib(type=List[int], factory=list)

    async def __aenter__(self) -> Union[int, List[int]]:
        # It's safe to run this in autocommit mode as fetching values from a
        # sequence ignores transaction semantics anyway.
        self.stream_ids = await self.id_gen._db.runInteraction(
            "_load_next_mult_id",
            self.id_gen._load_next_mult_id_txn,
            self.multiple_ids or 1,
            db_autocommit=True,
        )

        with self.id_gen._lock:
            self.id_gen._unfinished_ids.update(self.stream_ids)

        if self.multiple_ids is None:
            return self.stream_ids[0] * self.id_gen._return_factor
        else:
            return [i * self.id_gen._return_factor for i in self.stream_ids]

    async def __aexit__(self, exc_type, exc, tb):
        for i in self.stream_ids:
            self.id_gen._mark_id_as_finished(i)

        if exc_type is not None:
            return False

        # Update the `stream_positions` table with newly updated stream
        # ID (unless self._writers is not set in which case we don't
        # bother, as nothing will read it).
        #
        # We only do this on the success path so that the persisted current
        # position points to a persisted row with the correct instance name.
        #
        # We do this in autocommit mode as a) the upsert works correctly outside
        # transactions and b) reduces the amount of time the rows are locked
        # for. If we don't do this then we'll often hit serialization errors due
        # to the fact we default to REPEATABLE READ isolation levels.
        if self.id_gen._writers:
            await self.id_gen._db.runInteraction(
                "MultiWriterIdGenerator._update_table",
                self.id_gen._update_stream_positions_table_txn,
                db_autocommit=True,
            )

        return False
