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

import contextlib
import threading
from collections import deque
from typing import Dict, Set, Tuple

from typing_extensions import Deque

from synapse.storage.database import Database, LoggingTransaction


class IdGenerator(object):
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
    cur = db_conn.cursor()
    if step == 1:
        cur.execute("SELECT MAX(%s) FROM %s" % (column, table))
    else:
        cur.execute("SELECT MIN(%s) FROM %s" % (column, table))
    (val,) = cur.fetchone()
    cur.close()
    current_id = int(val) if val else step
    return (max if step > 0 else min)(current_id, step)


class StreamIdGenerator(object):
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
        with stream_id_gen.get_next() as stream_id:
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
            with stream_id_gen.get_next() as stream_id:
                # ... persist event ...
        """
        with self._lock:
            self._current += self._step
            next_id = self._current

            self._unfinished_ids.append(next_id)

        @contextlib.contextmanager
        def manager():
            try:
                yield next_id
            finally:
                with self._lock:
                    self._unfinished_ids.remove(next_id)

        return manager()

    def get_next_mult(self, n):
        """
        Usage:
            with stream_id_gen.get_next(n) as stream_ids:
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

        @contextlib.contextmanager
        def manager():
            try:
                yield next_ids
            finally:
                with self._lock:
                    for next_id in next_ids:
                        self._unfinished_ids.remove(next_id)

        return manager()

    def get_current_token(self):
        """Returns the maximum stream id such that all stream ids less than or
        equal to it have been successfully persisted.

        Returns:
            int
        """
        with self._lock:
            if self._unfinished_ids:
                return self._unfinished_ids[0] - self._step

            return self._current


class ChainedIdGenerator(object):
    """Used to generate new stream ids where the stream must be kept in sync
    with another stream. It generates pairs of IDs, the first element is an
    integer ID for this stream, the second element is the ID for the stream
    that this stream needs to be kept in sync with."""

    def __init__(self, chained_generator, db_conn, table, column):
        self.chained_generator = chained_generator
        self._table = table
        self._lock = threading.Lock()
        self._current_max = _load_current_id(db_conn, table, column)
        self._unfinished_ids = deque()  # type: Deque[Tuple[int, int]]

    def get_next(self):
        """
        Usage:
            with stream_id_gen.get_next() as (stream_id, chained_id):
                # ... persist event ...
        """
        with self._lock:
            self._current_max += 1
            next_id = self._current_max
            chained_id = self.chained_generator.get_current_token()

            self._unfinished_ids.append((next_id, chained_id))

        @contextlib.contextmanager
        def manager():
            try:
                yield (next_id, chained_id)
            finally:
                with self._lock:
                    self._unfinished_ids.remove((next_id, chained_id))

        return manager()

    def get_current_token(self):
        """Returns the maximum stream id such that all stream ids less than or
        equal to it have been successfully persisted.
        """
        with self._lock:
            if self._unfinished_ids:
                stream_id, chained_id = self._unfinished_ids[0]
                return stream_id - 1, chained_id

            return self._current_max, self.chained_generator.get_current_token()

    def advance(self, token: int):
        """Stub implementation for advancing the token when receiving updates
        over replication; raises an exception as this instance should be the
        only source of updates.
        """

        raise Exception(
            "Attempted to advance token on source for table %r", self._table
        )


class MultiWriterIdGenerator:
    """An ID generator that tracks a stream that can have multiple writers.

    Uses a Postgres sequence to coordinate ID assignment, but positions of other
    writers will only get updated when `advance` is called (by replication).

    Note: Only works with Postgres.

    Args:
        db_conn
        db
        instance_name: The name of this instance.
        table: Database table associated with stream.
        instance_column: Column that stores the row's writer's instance name
        id_column: Column that stores the stream ID.
        sequence_name: The name of the postgres sequence used to generate new
            IDs.
    """

    def __init__(
        self,
        db_conn,
        db: Database,
        instance_name: str,
        table: str,
        instance_column: str,
        id_column: str,
        sequence_name: str,
    ):
        self._db = db
        self._instance_name = instance_name
        self._sequence_name = sequence_name

        # We lock as some functions may be called from DB threads.
        self._lock = threading.Lock()

        self._current_positions = self._load_current_ids(
            db_conn, table, instance_column, id_column
        )

        # Set of local IDs that we're still processing. The current position
        # should be less than the minimum of this set (if not empty).
        self._unfinished_ids = set()  # type: Set[int]

    def _load_current_ids(
        self, db_conn, table: str, instance_column: str, id_column: str
    ) -> Dict[str, int]:
        sql = """
            SELECT %(instance)s, MAX(%(id)s) FROM %(table)s
            GROUP BY %(instance)s
        """ % {
            "instance": instance_column,
            "id": id_column,
            "table": table,
        }

        cur = db_conn.cursor()
        cur.execute(sql)

        # `cur` is an iterable over returned rows, which are 2-tuples.
        current_positions = dict(cur)

        cur.close()

        return current_positions

    def _load_next_id_txn(self, txn):
        txn.execute("SELECT nextval(?)", (self._sequence_name,))
        (next_id,) = txn.fetchone()
        return next_id

    async def get_next(self):
        """
        Usage:
            with await stream_id_gen.get_next() as stream_id:
                # ... persist event ...
        """
        next_id = await self._db.runInteraction("_load_next_id", self._load_next_id_txn)

        # Assert the fetched ID is actually greater than what we currently
        # believe the ID to be. If not, then the sequence and table have got
        # out of sync somehow.
        assert self.get_current_token() < next_id

        with self._lock:
            self._unfinished_ids.add(next_id)

        @contextlib.contextmanager
        def manager():
            try:
                yield next_id
            finally:
                self._mark_id_as_finished(next_id)

        return manager()

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

        return next_id

    def _mark_id_as_finished(self, next_id: int):
        """The ID has finished being processed so we should advance the
        current poistion if possible.
        """

        with self._lock:
            self._unfinished_ids.discard(next_id)

            # Figure out if its safe to advance the position by checking there
            # aren't any lower allocated IDs that are yet to finish.
            if all(c > next_id for c in self._unfinished_ids):
                curr = self._current_positions.get(self._instance_name, 0)
                self._current_positions[self._instance_name] = max(curr, next_id)

    def get_current_token(self, instance_name: str = None) -> int:
        """Gets the current position of a named writer (defaults to current
        instance).

        Returns 0 if we don't have a position for the named writer (likely due
        to it being a new writer).
        """

        if instance_name is None:
            instance_name = self._instance_name

        with self._lock:
            return self._current_positions.get(instance_name, 0)

    def get_positions(self) -> Dict[str, int]:
        """Get a copy of the current positon map.
        """

        with self._lock:
            return dict(self._current_positions)

    def advance(self, instance_name: str, new_id: int):
        """Advance the postion of the named writer to the given ID, if greater
        than existing entry.
        """

        with self._lock:
            self._current_positions[instance_name] = max(
                new_id, self._current_positions.get(instance_name, 0)
            )
