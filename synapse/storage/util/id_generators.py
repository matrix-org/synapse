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

from collections import deque
import contextlib
import threading


class IdGenerator(object):
    def __init__(self, db_conn, table, column):
        self.table = table
        self.column = column
        self._lock = threading.Lock()
        cur = db_conn.cursor()
        self._next_id = self._load_next_id(cur)
        cur.close()

    def _load_next_id(self, txn):
        txn.execute("SELECT MAX(%s) FROM %s" % (self.column, self.table,))
        val, = txn.fetchone()
        return val + 1 if val else 1

    def get_next(self):
        with self._lock:
            i = self._next_id
            self._next_id += 1
            return i


class StreamIdGenerator(object):
    """Used to generate new stream ids when persisting events while keeping
    track of which transactions have been completed.

    This allows us to get the "current" stream id, i.e. the stream id such that
    all ids less than or equal to it have completed. This handles the fact that
    persistence of events can complete out of order.

    Usage:
        with stream_id_gen.get_next() as stream_id:
            # ... persist event ...
    """
    def __init__(self, db_conn, table, column):
        self.table = table
        self.column = column

        self._lock = threading.Lock()

        cur = db_conn.cursor()
        self._current_max = self._load_current_max(cur)
        cur.close()

        self._unfinished_ids = deque()

    def _load_current_max(self, txn):
        txn.execute("SELECT MAX(%s) FROM %s" % (self.column, self.table))
        rows = txn.fetchall()
        val, = rows[0]
        return int(val) if val else 1

    def get_next(self):
        """
        Usage:
            with stream_id_gen.get_next() as stream_id:
                # ... persist event ...
        """
        with self._lock:
            self._current_max += 1
            next_id = self._current_max

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
            next_ids = range(self._current_max + 1, self._current_max + n + 1)
            self._current_max += n

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

    def get_max_token(self):
        """Returns the maximum stream id such that all stream ids less than or
        equal to it have been successfully persisted.
        """
        with self._lock:
            if self._unfinished_ids:
                return self._unfinished_ids[0] - 1

            return self._current_max
