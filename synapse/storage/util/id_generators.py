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
import heapq
import threading
from collections import deque
from typing import Dict, List, Set

from typing_extensions import Deque

from synapse.storage.database import DatabasePool, LoggingTransaction
from synapse.storage.util.sequence import PostgresSequenceGenerator


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
        with await stream_id_gen.get_next() as stream_id:
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

    async def get_next(self):
        """
        Usage:
            with await stream_id_gen.get_next() as stream_id:
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

    async def get_next_mult(self, n):
        """
        Usage:
            with await stream_id_gen.get_next(n) as stream_ids:
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
        db: DatabasePool,
        instance_name: str,
        table: str,
        instance_column: str,
        id_column: str,
        sequence_name: str,
    ):
        self._db = db
        self._instance_name = instance_name

        # We lock as some functions may be called from DB threads.
        self._lock = threading.Lock()

        self._current_positions = self._load_current_ids(
            db_conn, table, instance_column, id_column
        )

        # Set of local IDs that we're still processing. The current position
        # should be less than the minimum of this set (if not empty).
        self._unfinished_ids = set()  # type: Set[int]

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
        self._persisted_upto_position = (
            min(self._current_positions.values()) if self._current_positions else 0
        )
        self._known_persisted_positions = []  # type: List[int]

        self._sequence_gen = PostgresSequenceGenerator(sequence_name)

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

    def _load_next_id_txn(self, txn) -> int:
        return self._sequence_gen.get_next_id_txn(txn)

    def _load_next_mult_id_txn(self, txn, n: int) -> List[int]:
        return self._sequence_gen.get_next_mult_txn(txn, n)

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
        assert self.get_current_token_for_writer(self._instance_name) < next_id

        with self._lock:
            self._unfinished_ids.add(next_id)

        @contextlib.contextmanager
        def manager():
            try:
                yield next_id
            finally:
                self._mark_id_as_finished(next_id)

        return manager()

    async def get_next_mult(self, n: int):
        """
        Usage:
            with await stream_id_gen.get_next_mult(5) as stream_ids:
                # ... persist events ...
        """
        next_ids = await self._db.runInteraction(
            "_load_next_mult_id", self._load_next_mult_id_txn, n
        )

        # Assert the fetched ID is actually greater than any ID we've already
        # seen. If not, then the sequence and table have got out of sync
        # somehow.
        assert max(self.get_positions().values(), default=0) < min(next_ids)

        with self._lock:
            self._unfinished_ids.update(next_ids)

        @contextlib.contextmanager
        def manager():
            try:
                yield next_ids
            finally:
                for i in next_ids:
                    self._mark_id_as_finished(i)

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

    def get_current_token(self) -> int:
        """Returns the maximum stream id such that all stream ids less than or
        equal to it have been successfully persisted.
        """

        # Currently we don't support this operation, as it's not obvious how to
        # condense the stream positions of multiple writers into a single int.
        raise NotImplementedError()

    def get_current_token_for_writer(self, instance_name: str) -> int:
        """Returns the position of the given writer.
        """

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

            self._add_persisted_position(new_id)

    def get_persisted_upto_position(self) -> int:
        """Get the max position where all previous positions have been
        persisted.

        Note: In the worst case scenario this will be equal to the minimum
        position across writers. This means that the returned position here can
        lag if one writer doesn't write very often.
        """

        with self._lock:
            return self._persisted_upto_position

    def _add_persisted_position(self, new_id: int):
        """Record that we have persisted a position.

        This is used to keep the `_current_positions` up to date.
        """

        # We require that the lock is locked by caller
        assert self._lock.locked()

        heapq.heappush(self._known_persisted_positions, new_id)

        # We move the current min position up if the minimum current positions
        # of all instances is higher (since by definition all positions less
        # that that have been persisted).
        min_curr = min(self._current_positions.values())
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
