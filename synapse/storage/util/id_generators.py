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
        cur.execute("SELECT MAX(%s) FROM %s" % (column, table,))
    else:
        cur.execute("SELECT MIN(%s) FROM %s" % (column, table,))
    val, = cur.fetchone()
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
                self._current,
                _load_current_id(db_conn, table, column, step)
            )
        self._unfinished_ids = deque()

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
                self._step
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
        self._lock = threading.Lock()
        self._current_max = _load_current_id(db_conn, table, column)
        self._unfinished_ids = deque()

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
                return (stream_id - 1, chained_id)

            return (self._current_max, self.chained_generator.get_current_token())
