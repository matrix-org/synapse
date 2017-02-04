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
import logging

from synapse.api.errors import StoreError
from synapse.util.logcontext import LoggingContext, PreserveLoggingContext
from synapse.util.caches.dictionary_cache import DictionaryCache
from synapse.util.caches.descriptors import Cache
from synapse.util.caches import intern_dict
from synapse.storage.engines import PostgresEngine
import synapse.metrics


from twisted.internet import defer

import sys
import time
import threading
import os


CACHE_SIZE_FACTOR = float(os.environ.get("SYNAPSE_CACHE_FACTOR", 0.1))


logger = logging.getLogger(__name__)

sql_logger = logging.getLogger("synapse.storage.SQL")
transaction_logger = logging.getLogger("synapse.storage.txn")
perf_logger = logging.getLogger("synapse.storage.TIME")


metrics = synapse.metrics.get_metrics_for("synapse.storage")

sql_scheduling_timer = metrics.register_distribution("schedule_time")

sql_query_timer = metrics.register_distribution("query_time", labels=["verb"])
sql_txn_timer = metrics.register_distribution("transaction_time", labels=["desc"])


class LoggingTransaction(object):
    """An object that almost-transparently proxies for the 'txn' object
    passed to the constructor. Adds logging and metrics to the .execute()
    method."""
    __slots__ = ["txn", "name", "database_engine", "after_callbacks"]

    def __init__(self, txn, name, database_engine, after_callbacks):
        object.__setattr__(self, "txn", txn)
        object.__setattr__(self, "name", name)
        object.__setattr__(self, "database_engine", database_engine)
        object.__setattr__(self, "after_callbacks", after_callbacks)

    def call_after(self, callback, *args):
        """Call the given callback on the main twisted thread after the
        transaction has finished. Used to invalidate the caches on the
        correct thread.
        """
        self.after_callbacks.append((callback, args))

    def __getattr__(self, name):
        return getattr(self.txn, name)

    def __setattr__(self, name, value):
        setattr(self.txn, name, value)

    def execute(self, sql, *args):
        self._do_execute(self.txn.execute, sql, *args)

    def executemany(self, sql, *args):
        self._do_execute(self.txn.executemany, sql, *args)

    def _do_execute(self, func, sql, *args):
        # TODO(paul): Maybe use 'info' and 'debug' for values?
        sql_logger.debug("[SQL] {%s} %s", self.name, sql)

        sql = self.database_engine.convert_param_style(sql)
        if args:
            try:
                sql_logger.debug(
                    "[SQL values] {%s} %r",
                    self.name, args[0]
                )
            except:
                # Don't let logging failures stop SQL from working
                pass

        start = time.time() * 1000

        try:
            return func(
                sql, *args
            )
        except Exception as e:
            logger.debug("[SQL FAIL] {%s} %s", self.name, e)
            raise
        finally:
            msecs = (time.time() * 1000) - start
            sql_logger.debug("[SQL time] {%s} %f", self.name, msecs)
            sql_query_timer.inc_by(msecs, sql.split()[0])


class PerformanceCounters(object):
    def __init__(self):
        self.current_counters = {}
        self.previous_counters = {}

    def update(self, key, start_time, end_time=None):
        if end_time is None:
            end_time = time.time() * 1000
        duration = end_time - start_time
        count, cum_time = self.current_counters.get(key, (0, 0))
        count += 1
        cum_time += duration
        self.current_counters[key] = (count, cum_time)
        return end_time

    def interval(self, interval_duration, limit=3):
        counters = []
        for name, (count, cum_time) in self.current_counters.items():
            prev_count, prev_time = self.previous_counters.get(name, (0, 0))
            counters.append((
                (cum_time - prev_time) / interval_duration,
                count - prev_count,
                name
            ))

        self.previous_counters = dict(self.current_counters)

        counters.sort(reverse=True)

        top_n_counters = ", ".join(
            "%s(%d): %.3f%%" % (name, count, 100 * ratio)
            for ratio, count, name in counters[:limit]
        )

        return top_n_counters


class SQLBaseStore(object):
    _TXN_ID = 0

    def __init__(self, hs):
        self.hs = hs
        self._clock = hs.get_clock()
        self._db_pool = hs.get_db_pool()

        self._previous_txn_total_time = 0
        self._current_txn_total_time = 0
        self._previous_loop_ts = 0

        # TODO(paul): These can eventually be removed once the metrics code
        #   is running in mainline, and we have some nice monitoring frontends
        #   to watch it
        self._txn_perf_counters = PerformanceCounters()
        self._get_event_counters = PerformanceCounters()

        self._get_event_cache = Cache("*getEvent*", keylen=3,
                                      max_entries=hs.config.event_cache_size)

        self._state_group_cache = DictionaryCache(
            "*stateGroupCache*", 100000 * CACHE_SIZE_FACTOR
        )

        self._event_fetch_lock = threading.Condition()
        self._event_fetch_list = []
        self._event_fetch_ongoing = 0

        self._pending_ds = []

        self.database_engine = hs.database_engine

    def start_profiling(self):
        self._previous_loop_ts = self._clock.time_msec()

        def loop():
            curr = self._current_txn_total_time
            prev = self._previous_txn_total_time
            self._previous_txn_total_time = curr

            time_now = self._clock.time_msec()
            time_then = self._previous_loop_ts
            self._previous_loop_ts = time_now

            ratio = (curr - prev) / (time_now - time_then)

            top_three_counters = self._txn_perf_counters.interval(
                time_now - time_then, limit=3
            )

            top_3_event_counters = self._get_event_counters.interval(
                time_now - time_then, limit=3
            )

            perf_logger.info(
                "Total database time: %.3f%% {%s} {%s}",
                ratio * 100, top_three_counters, top_3_event_counters
            )

        self._clock.looping_call(loop, 10000)

    def _new_transaction(self, conn, desc, after_callbacks, logging_context,
                         func, *args, **kwargs):
        start = time.time() * 1000
        txn_id = self._TXN_ID

        # We don't really need these to be unique, so lets stop it from
        # growing really large.
        self._TXN_ID = (self._TXN_ID + 1) % (sys.maxint - 1)

        name = "%s-%x" % (desc, txn_id, )

        transaction_logger.debug("[TXN START] {%s}", name)

        try:
            i = 0
            N = 5
            while True:
                try:
                    txn = conn.cursor()
                    txn = LoggingTransaction(
                        txn, name, self.database_engine, after_callbacks
                    )
                    r = func(txn, *args, **kwargs)
                    conn.commit()
                    return r
                except self.database_engine.module.OperationalError as e:
                    # This can happen if the database disappears mid
                    # transaction.
                    logger.warn(
                        "[TXN OPERROR] {%s} %s %d/%d",
                        name, e, i, N
                    )
                    if i < N:
                        i += 1
                        try:
                            conn.rollback()
                        except self.database_engine.module.Error as e1:
                            logger.warn(
                                "[TXN EROLL] {%s} %s",
                                name, e1,
                            )
                        continue
                    raise
                except self.database_engine.module.DatabaseError as e:
                    if self.database_engine.is_deadlock(e):
                        logger.warn("[TXN DEADLOCK] {%s} %d/%d", name, i, N)
                        if i < N:
                            i += 1
                            try:
                                conn.rollback()
                            except self.database_engine.module.Error as e1:
                                logger.warn(
                                    "[TXN EROLL] {%s} %s",
                                    name, e1,
                                )
                            continue
                    raise
        except Exception as e:
            logger.debug("[TXN FAIL] {%s} %s", name, e)
            raise
        finally:
            end = time.time() * 1000
            duration = end - start

            if logging_context is not None:
                logging_context.add_database_transaction(duration)

            transaction_logger.debug("[TXN END] {%s} %f", name, duration)

            self._current_txn_total_time += duration
            self._txn_perf_counters.update(desc, start, end)
            sql_txn_timer.inc_by(duration, desc)

    @defer.inlineCallbacks
    def runInteraction(self, desc, func, *args, **kwargs):
        """Wraps the .runInteraction() method on the underlying db_pool."""
        current_context = LoggingContext.current_context()

        start_time = time.time() * 1000

        after_callbacks = []

        def inner_func(conn, *args, **kwargs):
            with LoggingContext("runInteraction") as context:
                sql_scheduling_timer.inc_by(time.time() * 1000 - start_time)

                if self.database_engine.is_connection_closed(conn):
                    logger.debug("Reconnecting closed database connection")
                    conn.reconnect()

                current_context.copy_to(context)
                return self._new_transaction(
                    conn, desc, after_callbacks, current_context,
                    func, *args, **kwargs
                )

        try:
            with PreserveLoggingContext():
                result = yield self._db_pool.runWithConnection(
                    inner_func, *args, **kwargs
                )
        finally:
            for after_callback, after_args in after_callbacks:
                after_callback(*after_args)
        defer.returnValue(result)

    @defer.inlineCallbacks
    def runWithConnection(self, func, *args, **kwargs):
        """Wraps the .runInteraction() method on the underlying db_pool."""
        current_context = LoggingContext.current_context()

        start_time = time.time() * 1000

        def inner_func(conn, *args, **kwargs):
            with LoggingContext("runWithConnection") as context:
                sql_scheduling_timer.inc_by(time.time() * 1000 - start_time)

                if self.database_engine.is_connection_closed(conn):
                    logger.debug("Reconnecting closed database connection")
                    conn.reconnect()

                current_context.copy_to(context)

                return func(conn, *args, **kwargs)

        with PreserveLoggingContext():
            result = yield self._db_pool.runWithConnection(
                inner_func, *args, **kwargs
            )

        defer.returnValue(result)

    @staticmethod
    def cursor_to_dict(cursor):
        """Converts a SQL cursor into an list of dicts.

        Args:
            cursor : The DBAPI cursor which has executed a query.
        Returns:
            A list of dicts where the key is the column header.
        """
        col_headers = list(column[0] for column in cursor.description)
        results = list(
            intern_dict(dict(zip(col_headers, row))) for row in cursor.fetchall()
        )
        return results

    def _execute(self, desc, decoder, query, *args):
        """Runs a single query for a result set.

        Args:
            decoder - The function which can resolve the cursor results to
                something meaningful.
            query - The query string to execute
            *args - Query args.
        Returns:
            The result of decoder(results)
        """
        def interaction(txn):
            txn.execute(query, args)
            if decoder:
                return decoder(txn)
            else:
                return txn.fetchall()

        return self.runInteraction(desc, interaction)

    # "Simple" SQL API methods that operate on a single table with no JOINs,
    # no complex WHERE clauses, just a dict of values for columns.

    @defer.inlineCallbacks
    def _simple_insert(self, table, values, or_ignore=False,
                       desc="_simple_insert"):
        """Executes an INSERT query on the named table.

        Args:
            table : string giving the table name
            values : dict of new column names and values for them

        Returns:
            bool: Whether the row was inserted or not. Only useful when
            `or_ignore` is True
        """
        try:
            yield self.runInteraction(
                desc,
                self._simple_insert_txn, table, values,
            )
        except self.database_engine.module.IntegrityError:
            # We have to do or_ignore flag at this layer, since we can't reuse
            # a cursor after we receive an error from the db.
            if not or_ignore:
                raise
            defer.returnValue(False)
        defer.returnValue(True)

    @staticmethod
    def _simple_insert_txn(txn, table, values):
        keys, vals = zip(*values.items())

        sql = "INSERT INTO %s (%s) VALUES(%s)" % (
            table,
            ", ".join(k for k in keys),
            ", ".join("?" for _ in keys)
        )

        txn.execute(sql, vals)

    @staticmethod
    def _simple_insert_many_txn(txn, table, values):
        if not values:
            return

        # This is a *slight* abomination to get a list of tuples of key names
        # and a list of tuples of value names.
        #
        # i.e. [{"a": 1, "b": 2}, {"c": 3, "d": 4}]
        #         => [("a", "b",), ("c", "d",)] and [(1, 2,), (3, 4,)]
        #
        # The sort is to ensure that we don't rely on dictionary iteration
        # order.
        keys, vals = zip(*[
            zip(
                *(sorted(i.items(), key=lambda kv: kv[0]))
            )
            for i in values
            if i
        ])

        for k in keys:
            if k != keys[0]:
                raise RuntimeError(
                    "All items must have the same keys"
                )

        sql = "INSERT INTO %s (%s) VALUES(%s)" % (
            table,
            ", ".join(k for k in keys[0]),
            ", ".join("?" for _ in keys[0])
        )

        txn.executemany(sql, vals)

    def _simple_upsert(self, table, keyvalues, values,
                       insertion_values={}, desc="_simple_upsert", lock=True):
        """
        Args:
            table (str): The table to upsert into
            keyvalues (dict): The unique key tables and their new values
            values (dict): The nonunique columns and their new values
            insertion_values (dict): key/values to use when inserting
        Returns:
            Deferred(bool): True if a new entry was created, False if an
                existing one was updated.
        """
        return self.runInteraction(
            desc,
            self._simple_upsert_txn, table, keyvalues, values, insertion_values,
            lock
        )

    def _simple_upsert_txn(self, txn, table, keyvalues, values, insertion_values={},
                           lock=True):
        # We need to lock the table :(, unless we're *really* careful
        if lock:
            self.database_engine.lock_table(txn, table)

        # Try to update
        sql = "UPDATE %s SET %s WHERE %s" % (
            table,
            ", ".join("%s = ?" % (k,) for k in values),
            " AND ".join("%s = ?" % (k,) for k in keyvalues)
        )
        sqlargs = values.values() + keyvalues.values()
        logger.debug(
            "[SQL] %s Args=%s",
            sql, sqlargs,
        )

        txn.execute(sql, sqlargs)
        if txn.rowcount == 0:
            # We didn't update and rows so insert a new one
            allvalues = {}
            allvalues.update(keyvalues)
            allvalues.update(values)
            allvalues.update(insertion_values)

            sql = "INSERT INTO %s (%s) VALUES (%s)" % (
                table,
                ", ".join(k for k in allvalues),
                ", ".join("?" for _ in allvalues)
            )
            logger.debug(
                "[SQL] %s Args=%s",
                sql, keyvalues.values(),
            )
            txn.execute(sql, allvalues.values())

            return True
        else:
            return False

    def _simple_select_one(self, table, keyvalues, retcols,
                           allow_none=False, desc="_simple_select_one"):
        """Executes a SELECT query on the named table, which is expected to
        return a single row, returning a single column from it.

        Args:
            table : string giving the table name
            keyvalues : dict of column names and values to select the row with
            retcols : list of strings giving the names of the columns to return

            allow_none : If true, return None instead of failing if the SELECT
              statement returns no rows
        """
        return self.runInteraction(
            desc,
            self._simple_select_one_txn,
            table, keyvalues, retcols, allow_none,
        )

    def _simple_select_one_onecol(self, table, keyvalues, retcol,
                                  allow_none=False,
                                  desc="_simple_select_one_onecol"):
        """Executes a SELECT query on the named table, which is expected to
        return a single row, returning a single column from it.

        Args:
            table : string giving the table name
            keyvalues : dict of column names and values to select the row with
            retcol : string giving the name of the column to return
        """
        return self.runInteraction(
            desc,
            self._simple_select_one_onecol_txn,
            table, keyvalues, retcol, allow_none=allow_none,
        )

    @classmethod
    def _simple_select_one_onecol_txn(cls, txn, table, keyvalues, retcol,
                                      allow_none=False):
        ret = cls._simple_select_onecol_txn(
            txn,
            table=table,
            keyvalues=keyvalues,
            retcol=retcol,
        )

        if ret:
            return ret[0]
        else:
            if allow_none:
                return None
            else:
                raise StoreError(404, "No row found")

    @staticmethod
    def _simple_select_onecol_txn(txn, table, keyvalues, retcol):
        if keyvalues:
            where = "WHERE %s" % " AND ".join("%s = ?" % k for k in keyvalues.keys())
        else:
            where = ""

        sql = (
            "SELECT %(retcol)s FROM %(table)s %(where)s"
        ) % {
            "retcol": retcol,
            "table": table,
            "where": where,
        }

        txn.execute(sql, keyvalues.values())

        return [r[0] for r in txn.fetchall()]

    def _simple_select_onecol(self, table, keyvalues, retcol,
                              desc="_simple_select_onecol"):
        """Executes a SELECT query on the named table, which returns a list
        comprising of the values of the named column from the selected rows.

        Args:
            table (str): table name
            keyvalues (dict): column names and values to select the rows with
            retcol (str): column whos value we wish to retrieve.

        Returns:
            Deferred: Results in a list
        """
        return self.runInteraction(
            desc,
            self._simple_select_onecol_txn,
            table, keyvalues, retcol
        )

    def _simple_select_list(self, table, keyvalues, retcols,
                            desc="_simple_select_list"):
        """Executes a SELECT query on the named table, which may return zero or
        more rows, returning the result as a list of dicts.

        Args:
            table (str): the table name
            keyvalues (dict[str, Any] | None):
                column names and values to select the rows with, or None to not
                apply a WHERE clause.
            retcols (iterable[str]): the names of the columns to return
        Returns:
            defer.Deferred: resolves to list[dict[str, Any]]
        """
        return self.runInteraction(
            desc,
            self._simple_select_list_txn,
            table, keyvalues, retcols
        )

    @classmethod
    def _simple_select_list_txn(cls, txn, table, keyvalues, retcols):
        """Executes a SELECT query on the named table, which may return zero or
        more rows, returning the result as a list of dicts.

        Args:
            txn : Transaction object
            table (str): the table name
            keyvalues (dict[str, T] | None):
                column names and values to select the rows with, or None to not
                apply a WHERE clause.
            retcols (iterable[str]): the names of the columns to return
        """
        if keyvalues:
            sql = "SELECT %s FROM %s WHERE %s" % (
                ", ".join(retcols),
                table,
                " AND ".join("%s = ?" % (k, ) for k in keyvalues)
            )
            txn.execute(sql, keyvalues.values())
        else:
            sql = "SELECT %s FROM %s" % (
                ", ".join(retcols),
                table
            )
            txn.execute(sql)

        return cls.cursor_to_dict(txn)

    @defer.inlineCallbacks
    def _simple_select_many_batch(self, table, column, iterable, retcols,
                                  keyvalues={}, desc="_simple_select_many_batch",
                                  batch_size=100):
        """Executes a SELECT query on the named table, which may return zero or
        more rows, returning the result as a list of dicts.

        Filters rows by if value of `column` is in `iterable`.

        Args:
            table : string giving the table name
            column : column name to test for inclusion against `iterable`
            iterable : list
            keyvalues : dict of column names and values to select the rows with
            retcols : list of strings giving the names of the columns to return
        """
        results = []

        if not iterable:
            defer.returnValue(results)

        chunks = [
            iterable[i:i + batch_size]
            for i in xrange(0, len(iterable), batch_size)
        ]
        for chunk in chunks:
            rows = yield self.runInteraction(
                desc,
                self._simple_select_many_txn,
                table, column, chunk, keyvalues, retcols
            )

            results.extend(rows)

        defer.returnValue(results)

    @classmethod
    def _simple_select_many_txn(cls, txn, table, column, iterable, keyvalues, retcols):
        """Executes a SELECT query on the named table, which may return zero or
        more rows, returning the result as a list of dicts.

        Filters rows by if value of `column` is in `iterable`.

        Args:
            txn : Transaction object
            table : string giving the table name
            column : column name to test for inclusion against `iterable`
            iterable : list
            keyvalues : dict of column names and values to select the rows with
            retcols : list of strings giving the names of the columns to return
        """
        if not iterable:
            return []

        sql = "SELECT %s FROM %s" % (", ".join(retcols), table)

        clauses = []
        values = []
        clauses.append(
            "%s IN (%s)" % (column, ",".join("?" for _ in iterable))
        )
        values.extend(iterable)

        for key, value in keyvalues.items():
            clauses.append("%s = ?" % (key,))
            values.append(value)

        if clauses:
            sql = "%s WHERE %s" % (
                sql,
                " AND ".join(clauses),
            )

        txn.execute(sql, values)
        return cls.cursor_to_dict(txn)

    def _simple_update_one(self, table, keyvalues, updatevalues,
                           desc="_simple_update_one"):
        """Executes an UPDATE query on the named table, setting new values for
        columns in a row matching the key values.

        Args:
            table : string giving the table name
            keyvalues : dict of column names and values to select the row with
            updatevalues : dict giving column names and values to update
            retcols : optional list of column names to return

        If present, retcols gives a list of column names on which to perform
        a SELECT statement *before* performing the UPDATE statement. The values
        of these will be returned in a dict.

        These are performed within the same transaction, allowing an atomic
        get-and-set.  This can be used to implement compare-and-set by putting
        the update column in the 'keyvalues' dict as well.
        """
        return self.runInteraction(
            desc,
            self._simple_update_one_txn,
            table, keyvalues, updatevalues,
        )

    @staticmethod
    def _simple_update_one_txn(txn, table, keyvalues, updatevalues):
        if keyvalues:
            where = "WHERE %s" % " AND ".join("%s = ?" % k for k in keyvalues.keys())
        else:
            where = ""

        update_sql = "UPDATE %s SET %s %s" % (
            table,
            ", ".join("%s = ?" % (k,) for k in updatevalues),
            where,
        )

        txn.execute(
            update_sql,
            updatevalues.values() + keyvalues.values()
        )

        if txn.rowcount == 0:
            raise StoreError(404, "No row found")
        if txn.rowcount > 1:
            raise StoreError(500, "More than one row matched")

    @staticmethod
    def _simple_select_one_txn(txn, table, keyvalues, retcols,
                               allow_none=False):
        select_sql = "SELECT %s FROM %s WHERE %s" % (
            ", ".join(retcols),
            table,
            " AND ".join("%s = ?" % (k,) for k in keyvalues)
        )

        txn.execute(select_sql, keyvalues.values())

        row = txn.fetchone()
        if not row:
            if allow_none:
                return None
            raise StoreError(404, "No row found")
        if txn.rowcount > 1:
            raise StoreError(500, "More than one row matched")

        return dict(zip(retcols, row))

    def _simple_delete_one(self, table, keyvalues, desc="_simple_delete_one"):
        """Executes a DELETE query on the named table, expecting to delete a
        single row.

        Args:
            table : string giving the table name
            keyvalues : dict of column names and values to select the row with
        """
        return self.runInteraction(
            desc, self._simple_delete_one_txn, table, keyvalues
        )

    @staticmethod
    def _simple_delete_one_txn(txn, table, keyvalues):
        """Executes a DELETE query on the named table, expecting to delete a
        single row.

        Args:
            table : string giving the table name
            keyvalues : dict of column names and values to select the row with
        """
        sql = "DELETE FROM %s WHERE %s" % (
            table,
            " AND ".join("%s = ?" % (k, ) for k in keyvalues)
        )

        txn.execute(sql, keyvalues.values())
        if txn.rowcount == 0:
            raise StoreError(404, "No row found")
        if txn.rowcount > 1:
            raise StoreError(500, "more than one row matched")

    def _simple_delete(self, table, keyvalues, desc):
        return self.runInteraction(
            desc, self._simple_delete_txn, table, keyvalues
        )

    @staticmethod
    def _simple_delete_txn(txn, table, keyvalues):
        sql = "DELETE FROM %s WHERE %s" % (
            table,
            " AND ".join("%s = ?" % (k, ) for k in keyvalues)
        )

        return txn.execute(sql, keyvalues.values())

    def _get_cache_dict(self, db_conn, table, entity_column, stream_column,
                        max_value, limit=100000):
        # Fetch a mapping of room_id -> max stream position for "recent" rooms.
        # It doesn't really matter how many we get, the StreamChangeCache will
        # do the right thing to ensure it respects the max size of cache.
        sql = (
            "SELECT %(entity)s, MAX(%(stream)s) FROM %(table)s"
            " WHERE %(stream)s > ? - %(limit)s"
            " GROUP BY %(entity)s"
        ) % {
            "table": table,
            "entity": entity_column,
            "stream": stream_column,
            "limit": limit,
        }

        sql = self.database_engine.convert_param_style(sql)

        txn = db_conn.cursor()
        txn.execute(sql, (int(max_value),))
        rows = txn.fetchall()
        txn.close()

        cache = {
            row[0]: int(row[1])
            for row in rows
        }

        if cache:
            min_val = min(cache.values())
        else:
            min_val = max_value

        return cache, min_val

    def _invalidate_cache_and_stream(self, txn, cache_func, keys):
        """Invalidates the cache and adds it to the cache stream so slaves
        will know to invalidate their caches.

        This should only be used to invalidate caches where slaves won't
        otherwise know from other replication streams that the cache should
        be invalidated.
        """
        txn.call_after(cache_func.invalidate, keys)

        if isinstance(self.database_engine, PostgresEngine):
            # get_next() returns a context manager which is designed to wrap
            # the transaction. However, we want to only get an ID when we want
            # to use it, here, so we need to call __enter__ manually, and have
            # __exit__ called after the transaction finishes.
            ctx = self._cache_id_gen.get_next()
            stream_id = ctx.__enter__()
            txn.call_after(ctx.__exit__, None, None, None)
            txn.call_after(self.hs.get_notifier().on_new_replication_data)

            self._simple_insert_txn(
                txn,
                table="cache_invalidation_stream",
                values={
                    "stream_id": stream_id,
                    "cache_func": cache_func.__name__,
                    "keys": list(keys),
                    "invalidation_ts": self.clock.time_msec(),
                }
            )

    def get_all_updated_caches(self, last_id, current_id, limit):
        if last_id == current_id:
            return defer.succeed([])

        def get_all_updated_caches_txn(txn):
            # We purposefully don't bound by the current token, as we want to
            # send across cache invalidations as quickly as possible. Cache
            # invalidations are idempotent, so duplicates are fine.
            sql = (
                "SELECT stream_id, cache_func, keys, invalidation_ts"
                " FROM cache_invalidation_stream"
                " WHERE stream_id > ? ORDER BY stream_id ASC LIMIT ?"
            )
            txn.execute(sql, (last_id, limit,))
            return txn.fetchall()
        return self.runInteraction(
            "get_all_updated_caches", get_all_updated_caches_txn
        )

    def get_cache_stream_token(self):
        if self._cache_id_gen:
            return self._cache_id_gen.get_current_token()
        else:
            return 0


class _RollbackButIsFineException(Exception):
    """ This exception is used to rollback a transaction without implying
    something went wrong.
    """
    pass
