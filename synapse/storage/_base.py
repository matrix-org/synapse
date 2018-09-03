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
import sys
import threading
import time

from six import PY2, iteritems, iterkeys, itervalues
from six.moves import intern, range

from canonicaljson import json
from prometheus_client import Histogram

from twisted.internet import defer

from synapse.api.errors import StoreError
from synapse.storage.engines import PostgresEngine
from synapse.util.caches.descriptors import Cache
from synapse.util.logcontext import LoggingContext, PreserveLoggingContext

logger = logging.getLogger(__name__)

try:
    MAX_TXN_ID = sys.maxint - 1
except AttributeError:
    # python 3 does not have a maximum int value
    MAX_TXN_ID = 2**63 - 1

sql_logger = logging.getLogger("synapse.storage.SQL")
transaction_logger = logging.getLogger("synapse.storage.txn")
perf_logger = logging.getLogger("synapse.storage.TIME")

sql_scheduling_timer = Histogram("synapse_storage_schedule_time", "sec")

sql_query_timer = Histogram("synapse_storage_query_time", "sec", ["verb"])
sql_txn_timer = Histogram("synapse_storage_transaction_time", "sec", ["desc"])


class LoggingTransaction(object):
    """An object that almost-transparently proxies for the 'txn' object
    passed to the constructor. Adds logging and metrics to the .execute()
    method."""
    __slots__ = [
        "txn", "name", "database_engine", "after_callbacks", "exception_callbacks",
    ]

    def __init__(self, txn, name, database_engine, after_callbacks,
                 exception_callbacks):
        object.__setattr__(self, "txn", txn)
        object.__setattr__(self, "name", name)
        object.__setattr__(self, "database_engine", database_engine)
        object.__setattr__(self, "after_callbacks", after_callbacks)
        object.__setattr__(self, "exception_callbacks", exception_callbacks)

    def call_after(self, callback, *args, **kwargs):
        """Call the given callback on the main twisted thread after the
        transaction has finished. Used to invalidate the caches on the
        correct thread.
        """
        self.after_callbacks.append((callback, args, kwargs))

    def call_on_exception(self, callback, *args, **kwargs):
        self.exception_callbacks.append((callback, args, kwargs))

    def __getattr__(self, name):
        return getattr(self.txn, name)

    def __setattr__(self, name, value):
        setattr(self.txn, name, value)

    def __iter__(self):
        return self.txn.__iter__()

    def execute(self, sql, *args):
        self._do_execute(self.txn.execute, sql, *args)

    def executemany(self, sql, *args):
        self._do_execute(self.txn.executemany, sql, *args)

    def _make_sql_one_line(self, sql):
        "Strip newlines out of SQL so that the loggers in the DB are on one line"
        return " ".join(l.strip() for l in sql.splitlines() if l.strip())

    def _do_execute(self, func, sql, *args):
        sql = self._make_sql_one_line(sql)

        # TODO(paul): Maybe use 'info' and 'debug' for values?
        sql_logger.debug("[SQL] {%s} %s", self.name, sql)

        sql = self.database_engine.convert_param_style(sql)
        if args:
            try:
                sql_logger.debug(
                    "[SQL values] {%s} %r",
                    self.name, args[0]
                )
            except Exception:
                # Don't let logging failures stop SQL from working
                pass

        start = time.time()

        try:
            return func(
                sql, *args
            )
        except Exception as e:
            logger.debug("[SQL FAIL] {%s} %s", self.name, e)
            raise
        finally:
            secs = time.time() - start
            sql_logger.debug("[SQL time] {%s} %f sec", self.name, secs)
            sql_query_timer.labels(sql.split()[0]).observe(secs)


class PerformanceCounters(object):
    def __init__(self):
        self.current_counters = {}
        self.previous_counters = {}

    def update(self, key, start_time, end_time=None):
        if end_time is None:
            end_time = time.time()
        duration = end_time - start_time
        count, cum_time = self.current_counters.get(key, (0, 0))
        count += 1
        cum_time += duration
        self.current_counters[key] = (count, cum_time)
        return end_time

    def interval(self, interval_duration, limit=3):
        counters = []
        for name, (count, cum_time) in iteritems(self.current_counters):
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

    def __init__(self, db_conn, hs):
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

    def _new_transaction(self, conn, desc, after_callbacks, exception_callbacks,
                         func, *args, **kwargs):
        start = time.time()
        txn_id = self._TXN_ID

        # We don't really need these to be unique, so lets stop it from
        # growing really large.
        self._TXN_ID = (self._TXN_ID + 1) % (MAX_TXN_ID)

        name = "%s-%x" % (desc, txn_id, )

        transaction_logger.debug("[TXN START] {%s}", name)

        try:
            i = 0
            N = 5
            while True:
                try:
                    txn = conn.cursor()
                    txn = LoggingTransaction(
                        txn, name, self.database_engine, after_callbacks,
                        exception_callbacks,
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
            end = time.time()
            duration = end - start

            LoggingContext.current_context().add_database_transaction(duration)

            transaction_logger.debug("[TXN END] {%s} %f sec", name, duration)

            self._current_txn_total_time += duration
            self._txn_perf_counters.update(desc, start, end)
            sql_txn_timer.labels(desc).observe(duration)

    @defer.inlineCallbacks
    def runInteraction(self, desc, func, *args, **kwargs):
        """Starts a transaction on the database and runs a given function

        Arguments:
            desc (str): description of the transaction, for logging and metrics
            func (func): callback function, which will be called with a
                database transaction (twisted.enterprise.adbapi.Transaction) as
                its first argument, followed by `args` and `kwargs`.

            args (list): positional args to pass to `func`
            kwargs (dict): named args to pass to `func`

        Returns:
            Deferred: The result of func
        """
        after_callbacks = []
        exception_callbacks = []

        if LoggingContext.current_context() == LoggingContext.sentinel:
            logger.warn(
                "Starting db txn '%s' from sentinel context",
                desc,
            )

        try:
            result = yield self.runWithConnection(
                self._new_transaction,
                desc, after_callbacks, exception_callbacks, func,
                *args, **kwargs
            )

            for after_callback, after_args, after_kwargs in after_callbacks:
                after_callback(*after_args, **after_kwargs)
        except:  # noqa: E722, as we reraise the exception this is fine.
            for after_callback, after_args, after_kwargs in exception_callbacks:
                after_callback(*after_args, **after_kwargs)
            raise

        defer.returnValue(result)

    @defer.inlineCallbacks
    def runWithConnection(self, func, *args, **kwargs):
        """Wraps the .runWithConnection() method on the underlying db_pool.

        Arguments:
            func (func): callback function, which will be called with a
                database connection (twisted.enterprise.adbapi.Connection) as
                its first argument, followed by `args` and `kwargs`.
            args (list): positional args to pass to `func`
            kwargs (dict): named args to pass to `func`

        Returns:
            Deferred: The result of func
        """
        parent_context = LoggingContext.current_context()
        if parent_context == LoggingContext.sentinel:
            logger.warn(
                "Starting db connection from sentinel context: metrics will be lost",
            )
            parent_context = None

        start_time = time.time()

        def inner_func(conn, *args, **kwargs):
            with LoggingContext("runWithConnection", parent_context) as context:
                sched_duration_sec = time.time() - start_time
                sql_scheduling_timer.observe(sched_duration_sec)
                context.add_database_scheduled(sched_duration_sec)

                if self.database_engine.is_connection_closed(conn):
                    logger.debug("Reconnecting closed database connection")
                    conn.reconnect()

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
        col_headers = list(intern(str(column[0])) for column in cursor.description)
        results = list(
            dict(zip(col_headers, row)) for row in cursor
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

    def _simple_insert_many(self, table, values, desc):
        return self.runInteraction(
            desc, self._simple_insert_many_txn, table, values
        )

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

    @defer.inlineCallbacks
    def _simple_upsert(self, table, keyvalues, values,
                       insertion_values={}, desc="_simple_upsert", lock=True):
        """

        `lock` should generally be set to True (the default), but can be set
        to False if either of the following are true:

        * there is a UNIQUE INDEX on the key columns. In this case a conflict
          will cause an IntegrityError in which case this function will retry
          the update.

        * we somehow know that we are the only thread which will be updating
          this table.

        Args:
            table (str): The table to upsert into
            keyvalues (dict): The unique key tables and their new values
            values (dict): The nonunique columns and their new values
            insertion_values (dict): additional key/values to use only when
                inserting
            lock (bool): True to lock the table when doing the upsert.
        Returns:
            Deferred(bool): True if a new entry was created, False if an
                existing one was updated.
        """
        attempts = 0
        while True:
            try:
                result = yield self.runInteraction(
                    desc,
                    self._simple_upsert_txn, table, keyvalues, values, insertion_values,
                    lock=lock
                )
                defer.returnValue(result)
            except self.database_engine.module.IntegrityError as e:
                attempts += 1
                if attempts >= 5:
                    # don't retry forever, because things other than races
                    # can cause IntegrityErrors
                    raise

                # presumably we raced with another transaction: let's retry.
                logger.warn(
                    "IntegrityError when upserting into %s; retrying: %s",
                    table, e
                )

    def _simple_upsert_txn(self, txn, table, keyvalues, values, insertion_values={},
                           lock=True):
        # We need to lock the table :(, unless we're *really* careful
        if lock:
            self.database_engine.lock_table(txn, table)

        # First try to update.
        sql = "UPDATE %s SET %s WHERE %s" % (
            table,
            ", ".join("%s = ?" % (k,) for k in values),
            " AND ".join("%s = ?" % (k,) for k in keyvalues)
        )
        sqlargs = list(values.values()) + list(keyvalues.values())

        txn.execute(sql, sqlargs)
        if txn.rowcount > 0:
            # successfully updated at least one row.
            return False

        # We didn't update any rows so insert a new one
        allvalues = {}
        allvalues.update(keyvalues)
        allvalues.update(values)
        allvalues.update(insertion_values)

        sql = "INSERT INTO %s (%s) VALUES (%s)" % (
            table,
            ", ".join(k for k in allvalues),
            ", ".join("?" for _ in allvalues)
        )
        txn.execute(sql, list(allvalues.values()))
        # successfully inserted
        return True

    def _simple_select_one(self, table, keyvalues, retcols,
                           allow_none=False, desc="_simple_select_one"):
        """Executes a SELECT query on the named table, which is expected to
        return a single row, returning multiple columns from it.

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
        sql = (
            "SELECT %(retcol)s FROM %(table)s"
        ) % {
            "retcol": retcol,
            "table": table,
        }

        if keyvalues:
            sql += " WHERE %s" % " AND ".join("%s = ?" % k for k in iterkeys(keyvalues))
            txn.execute(sql, list(keyvalues.values()))
        else:
            txn.execute(sql)

        return [r[0] for r in txn]

    def _simple_select_onecol(self, table, keyvalues, retcol,
                              desc="_simple_select_onecol"):
        """Executes a SELECT query on the named table, which returns a list
        comprising of the values of the named column from the selected rows.

        Args:
            table (str): table name
            keyvalues (dict|None): column names and values to select the rows with
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
            txn.execute(sql, list(keyvalues.values()))
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

        # iterables can not be sliced, so convert it to a list first
        it_list = list(iterable)

        chunks = [
            it_list[i:i + batch_size]
            for i in range(0, len(it_list), batch_size)
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

        for key, value in iteritems(keyvalues):
            clauses.append("%s = ?" % (key,))
            values.append(value)

        if clauses:
            sql = "%s WHERE %s" % (
                sql,
                " AND ".join(clauses),
            )

        txn.execute(sql, values)
        return cls.cursor_to_dict(txn)

    def _simple_update(self, table, keyvalues, updatevalues, desc):
        return self.runInteraction(
            desc,
            self._simple_update_txn,
            table, keyvalues, updatevalues,
        )

    @staticmethod
    def _simple_update_txn(txn, table, keyvalues, updatevalues):
        if keyvalues:
            where = "WHERE %s" % " AND ".join("%s = ?" % k for k in iterkeys(keyvalues))
        else:
            where = ""

        update_sql = "UPDATE %s SET %s %s" % (
            table,
            ", ".join("%s = ?" % (k,) for k in updatevalues),
            where,
        )

        txn.execute(
            update_sql,
            list(updatevalues.values()) + list(keyvalues.values())
        )

        return txn.rowcount

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

    @classmethod
    def _simple_update_one_txn(cls, txn, table, keyvalues, updatevalues):
        rowcount = cls._simple_update_txn(txn, table, keyvalues, updatevalues)

        if rowcount == 0:
            raise StoreError(404, "No row found")
        if rowcount > 1:
            raise StoreError(500, "More than one row matched")

    @staticmethod
    def _simple_select_one_txn(txn, table, keyvalues, retcols,
                               allow_none=False):
        select_sql = "SELECT %s FROM %s WHERE %s" % (
            ", ".join(retcols),
            table,
            " AND ".join("%s = ?" % (k,) for k in keyvalues)
        )

        txn.execute(select_sql, list(keyvalues.values()))

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

        txn.execute(sql, list(keyvalues.values()))
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

        return txn.execute(sql, list(keyvalues.values()))

    def _simple_delete_many(self, table, column, iterable, keyvalues, desc):
        return self.runInteraction(
            desc, self._simple_delete_many_txn, table, column, iterable, keyvalues
        )

    @staticmethod
    def _simple_delete_many_txn(txn, table, column, iterable, keyvalues):
        """Executes a DELETE query on the named table.

        Filters rows by if value of `column` is in `iterable`.

        Args:
            txn : Transaction object
            table : string giving the table name
            column : column name to test for inclusion against `iterable`
            iterable : list
            keyvalues : dict of column names and values to select the rows with
        """
        if not iterable:
            return

        sql = "DELETE FROM %s" % table

        clauses = []
        values = []
        clauses.append(
            "%s IN (%s)" % (column, ",".join("?" for _ in iterable))
        )
        values.extend(iterable)

        for key, value in iteritems(keyvalues):
            clauses.append("%s = ?" % (key,))
            values.append(value)

        if clauses:
            sql = "%s WHERE %s" % (
                sql,
                " AND ".join(clauses),
            )
        return txn.execute(sql, values)

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

        cache = {
            row[0]: int(row[1])
            for row in txn
        }

        txn.close()

        if cache:
            min_val = min(itervalues(cache))
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
            txn.call_on_exception(ctx.__exit__, None, None, None)
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

    def _simple_select_list_paginate(self, table, keyvalues, pagevalues, retcols,
                                     desc="_simple_select_list_paginate"):
        """Executes a SELECT query on the named table with start and limit,
        of row numbers, which may return zero or number of rows from start to limit,
        returning the result as a list of dicts.

        Args:
            table (str): the table name
            keyvalues (dict[str, Any] | None):
                column names and values to select the rows with, or None to not
                apply a WHERE clause.
            retcols (iterable[str]): the names of the columns to return
            order (str): order the select by this column
            start (int): start number to begin the query from
            limit (int): number of rows to reterive
        Returns:
            defer.Deferred: resolves to list[dict[str, Any]]
        """
        return self.runInteraction(
            desc,
            self._simple_select_list_paginate_txn,
            table, keyvalues, pagevalues, retcols
        )

    @classmethod
    def _simple_select_list_paginate_txn(cls, txn, table, keyvalues, pagevalues, retcols):
        """Executes a SELECT query on the named table with start and limit,
        of row numbers, which may return zero or number of rows from start to limit,
        returning the result as a list of dicts.

        Args:
            txn : Transaction object
            table (str): the table name
            keyvalues (dict[str, T] | None):
                column names and values to select the rows with, or None to not
                apply a WHERE clause.
            pagevalues ([]):
                order (str): order the select by this column
                start (int): start number to begin the query from
                limit (int): number of rows to reterive
            retcols (iterable[str]): the names of the columns to return
        Returns:
            defer.Deferred: resolves to list[dict[str, Any]]

        """
        if keyvalues:
            sql = "SELECT %s FROM %s WHERE %s ORDER BY %s" % (
                ", ".join(retcols),
                table,
                " AND ".join("%s = ?" % (k,) for k in keyvalues),
                " ? ASC LIMIT ? OFFSET ?"
            )
            txn.execute(sql, list(keyvalues.values()) + list(pagevalues))
        else:
            sql = "SELECT %s FROM %s ORDER BY %s" % (
                ", ".join(retcols),
                table,
                " ? ASC LIMIT ? OFFSET ?"
            )
            txn.execute(sql, pagevalues)

        return cls.cursor_to_dict(txn)

    @defer.inlineCallbacks
    def get_user_list_paginate(self, table, keyvalues, pagevalues, retcols,
                               desc="get_user_list_paginate"):
        """Get a list of users from start row to a limit number of rows. This will
        return a json object with users and total number of users in users list.

        Args:
            table (str): the table name
            keyvalues (dict[str, Any] | None):
                column names and values to select the rows with, or None to not
                apply a WHERE clause.
            pagevalues ([]):
                order (str): order the select by this column
                start (int): start number to begin the query from
                limit (int): number of rows to reterive
            retcols (iterable[str]): the names of the columns to return
        Returns:
            defer.Deferred: resolves to json object {list[dict[str, Any]], count}
        """
        users = yield self.runInteraction(
            desc,
            self._simple_select_list_paginate_txn,
            table, keyvalues, pagevalues, retcols
        )
        count = yield self.runInteraction(
            desc,
            self.get_user_count_txn
        )
        retval = {
            "users": users,
            "total": count
        }
        defer.returnValue(retval)

    def get_user_count_txn(self, txn):
        """Get a total number of registered users in the users list.

        Args:
            txn : Transaction object
        Returns:
            int : number of users
        """
        sql_count = "SELECT COUNT(*) FROM users WHERE is_guest = 0;"
        txn.execute(sql_count)
        return txn.fetchone()[0]

    def _simple_search_list(self, table, term, col, retcols,
                            desc="_simple_search_list"):
        """Executes a SELECT query on the named table, which may return zero or
        more rows, returning the result as a list of dicts.

        Args:
            table (str): the table name
            term (str | None):
                term for searching the table matched to a column.
            col (str): column to query term should be matched to
            retcols (iterable[str]): the names of the columns to return
        Returns:
            defer.Deferred: resolves to list[dict[str, Any]] or None
        """

        return self.runInteraction(
            desc,
            self._simple_search_list_txn,
            table, term, col, retcols
        )

    @classmethod
    def _simple_search_list_txn(cls, txn, table, term, col, retcols):
        """Executes a SELECT query on the named table, which may return zero or
        more rows, returning the result as a list of dicts.

        Args:
            txn : Transaction object
            table (str): the table name
            term (str | None):
                term for searching the table matched to a column.
            col (str): column to query term should be matched to
            retcols (iterable[str]): the names of the columns to return
        Returns:
            defer.Deferred: resolves to list[dict[str, Any]] or None
        """
        if term:
            sql = "SELECT %s FROM %s WHERE %s LIKE ?" % (
                ", ".join(retcols),
                table,
                col
            )
            termvalues = ["%%" + term + "%%"]
            txn.execute(sql, termvalues)
        else:
            return 0

        return cls.cursor_to_dict(txn)


class _RollbackButIsFineException(Exception):
    """ This exception is used to rollback a transaction without implying
    something went wrong.
    """
    pass


def db_to_json(db_content):
    """
    Take some data from a database row and return a JSON-decoded object.

    Args:
        db_content (memoryview|buffer|bytes|bytearray|unicode)
    """
    # psycopg2 on Python 3 returns memoryview objects, which we need to
    # cast to bytes to decode
    if isinstance(db_content, memoryview):
        db_content = db_content.tobytes()

    # psycopg2 on Python 2 returns buffer objects, which we need to cast to
    # bytes to decode
    if PY2 and isinstance(db_content, buffer):
        db_content = bytes(db_content)

    # Decode it to a Unicode string before feeding it to json.loads, so we
    # consistenty get a Unicode-containing object out.
    if isinstance(db_content, (bytes, bytearray)):
        db_content = db_content.decode('utf8')

    try:
        return json.loads(db_content)
    except Exception:
        logging.warning("Tried to decode '%r' as JSON and failed", db_content)
        raise
