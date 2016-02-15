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

from twisted.internet import defer

from collections import deque
import contextlib
import threading


class IdGenerator(object):
    def __init__(self, table, column, store):
        self.table = table
        self.column = column
        self.store = store
        self._lock = threading.Lock()
        self._next_id = None

    @defer.inlineCallbacks
    def get_next(self):
        if self._next_id is None:
            yield self.store.runInteraction(
                "IdGenerator_%s" % (self.table,),
                self.get_next_txn,
            )

        with self._lock:
            i = self._next_id
            self._next_id += 1
            defer.returnValue(i)

    def get_next_txn(self, txn):
        with self._lock:
            if self._next_id:
                i = self._next_id
                self._next_id += 1
                return i
            else:
                txn.execute(
                    "SELECT MAX(%s) FROM %s" % (self.column, self.table,)
                )

                val, = txn.fetchone()
                cur = val or 0
                cur += 1
                self._next_id = cur + 1

                return cur


class StreamIdGenerator(object):
    """Used to generate new stream ids when persisting events while keeping
    track of which transactions have been completed.

    This allows us to get the "current" stream id, i.e. the stream id such that
    all ids less than or equal to it have completed. This handles the fact that
    persistence of events can complete out of order.

    Usage:
        with stream_id_gen.get_next_txn(txn) as stream_id:
            # ... persist event ...
    """
    def __init__(self, db_conn, table, column):
        self.table = table
        self.column = column

        self._lock = threading.Lock()

        cur = db_conn.cursor()
        self._current_max = self._get_or_compute_current_max(cur)
        cur.close()

        self._unfinished_ids = deque()

    def get_next(self, store):
        """
        Usage:
            with yield stream_id_gen.get_next as stream_id:
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

    def get_next_mult(self, store, n):
        """
        Usage:
            with yield stream_id_gen.get_next(store, n) as stream_ids:
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

    def get_max_token(self, *args):
        """Returns the maximum stream id such that all stream ids less than or
        equal to it have been successfully persisted.

        Used to take a DataStore param, which is no longer needed.
        """
        with self._lock:
            if self._unfinished_ids:
                return self._unfinished_ids[0] - 1

            return self._current_max

    def _get_or_compute_current_max(self, txn):
        with self._lock:
            txn.execute("SELECT MAX(%s) FROM %s" % (self.column, self.table))
            rows = txn.fetchall()
            val, = rows[0]

            self._current_max = int(val) if val else 1

            return self._current_max
