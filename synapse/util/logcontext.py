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

""" Thread-local-alike tracking of log contexts within synapse

This module provides objects and utilities for tracking contexts through
synapse code, so that log lines can include a request identifier, and so that
CPU and database activity can be accounted for against the request that caused
them.

See doc/log_contexts.rst for details on how this works.
"""

import logging
import threading
import types

from twisted.internet import defer, threads

logger = logging.getLogger(__name__)

try:
    import resource

    # Python doesn't ship with a definition of RUSAGE_THREAD but it's defined
    # to be 1 on linux so we hard code it.
    RUSAGE_THREAD = 1

    # If the system doesn't support RUSAGE_THREAD then this should throw an
    # exception.
    resource.getrusage(RUSAGE_THREAD)

    def get_thread_resource_usage():
        return resource.getrusage(RUSAGE_THREAD)


except Exception:
    # If the system doesn't support resource.getrusage(RUSAGE_THREAD) then we
    # won't track resource usage by returning None.
    def get_thread_resource_usage():
        return None


class ContextResourceUsage(object):
    """Object for tracking the resources used by a log context

    Attributes:
        ru_utime (float): user CPU time (in seconds)
        ru_stime (float): system CPU time (in seconds)
        db_txn_count (int): number of database transactions done
        db_sched_duration_sec (float): amount of time spent waiting for a
            database connection
        db_txn_duration_sec (float): amount of time spent doing database
            transactions (excluding scheduling time)
        evt_db_fetch_count (int): number of events requested from the database
    """

    __slots__ = [
        "ru_stime",
        "ru_utime",
        "db_txn_count",
        "db_txn_duration_sec",
        "db_sched_duration_sec",
        "evt_db_fetch_count",
    ]

    def __init__(self, copy_from=None):
        """Create a new ContextResourceUsage

        Args:
            copy_from (ContextResourceUsage|None): if not None, an object to
                copy stats from
        """
        if copy_from is None:
            self.reset()
        else:
            self.ru_utime = copy_from.ru_utime
            self.ru_stime = copy_from.ru_stime
            self.db_txn_count = copy_from.db_txn_count

            self.db_txn_duration_sec = copy_from.db_txn_duration_sec
            self.db_sched_duration_sec = copy_from.db_sched_duration_sec
            self.evt_db_fetch_count = copy_from.evt_db_fetch_count

    def copy(self):
        return ContextResourceUsage(copy_from=self)

    def reset(self):
        self.ru_stime = 0.0
        self.ru_utime = 0.0
        self.db_txn_count = 0

        self.db_txn_duration_sec = 0
        self.db_sched_duration_sec = 0
        self.evt_db_fetch_count = 0

    def __repr__(self):
        return (
            "<ContextResourceUsage ru_stime='%r', ru_utime='%r', "
            "db_txn_count='%r', db_txn_duration_sec='%r', "
            "db_sched_duration_sec='%r', evt_db_fetch_count='%r'>"
        ) % (
            self.ru_stime,
            self.ru_utime,
            self.db_txn_count,
            self.db_txn_duration_sec,
            self.db_sched_duration_sec,
            self.evt_db_fetch_count,
        )

    def __iadd__(self, other):
        """Add another ContextResourceUsage's stats to this one's.

        Args:
            other (ContextResourceUsage): the other resource usage object
        """
        self.ru_utime += other.ru_utime
        self.ru_stime += other.ru_stime
        self.db_txn_count += other.db_txn_count
        self.db_txn_duration_sec += other.db_txn_duration_sec
        self.db_sched_duration_sec += other.db_sched_duration_sec
        self.evt_db_fetch_count += other.evt_db_fetch_count
        return self

    def __isub__(self, other):
        self.ru_utime -= other.ru_utime
        self.ru_stime -= other.ru_stime
        self.db_txn_count -= other.db_txn_count
        self.db_txn_duration_sec -= other.db_txn_duration_sec
        self.db_sched_duration_sec -= other.db_sched_duration_sec
        self.evt_db_fetch_count -= other.evt_db_fetch_count
        return self

    def __add__(self, other):
        res = ContextResourceUsage(copy_from=self)
        res += other
        return res

    def __sub__(self, other):
        res = ContextResourceUsage(copy_from=self)
        res -= other
        return res


class LoggingContext(object):
    """Additional context for log formatting. Contexts are scoped within a
    "with" block.

    If a parent is given when creating a new context, then:
        - logging fields are copied from the parent to the new context on entry
        - when the new context exits, the cpu usage stats are copied from the
          child to the parent

    Args:
        name (str): Name for the context for debugging.
        parent_context (LoggingContext|None): The parent of the new context
    """

    __slots__ = [
        "previous_context",
        "name",
        "parent_context",
        "_resource_usage",
        "usage_start",
        "main_thread",
        "alive",
        "request",
        "tag",
    ]

    thread_local = threading.local()

    class Sentinel(object):
        """Sentinel to represent the root context"""

        __slots__ = []

        def __str__(self):
            return "sentinel"

        def copy_to(self, record):
            pass

        def start(self):
            pass

        def stop(self):
            pass

        def add_database_transaction(self, duration_sec):
            pass

        def add_database_scheduled(self, sched_sec):
            pass

        def record_event_fetch(self, event_count):
            pass

        def __nonzero__(self):
            return False

        __bool__ = __nonzero__  # python3

    sentinel = Sentinel()

    def __init__(self, name=None, parent_context=None, request=None):
        self.previous_context = LoggingContext.current_context()
        self.name = name

        # track the resources used by this context so far
        self._resource_usage = ContextResourceUsage()

        # If alive has the thread resource usage when the logcontext last
        # became active.
        self.usage_start = None

        self.main_thread = threading.current_thread()
        self.request = None
        self.tag = ""
        self.alive = True

        self.parent_context = parent_context

        if self.parent_context is not None:
            self.parent_context.copy_to(self)

        if request is not None:
            # the request param overrides the request from the parent context
            self.request = request

    def __str__(self):
        if self.request:
            return str(self.request)
        return "%s@%x" % (self.name, id(self))

    @classmethod
    def current_context(cls):
        """Get the current logging context from thread local storage

        Returns:
            LoggingContext: the current logging context
        """
        return getattr(cls.thread_local, "current_context", cls.sentinel)

    @classmethod
    def set_current_context(cls, context):
        """Set the current logging context in thread local storage
        Args:
            context(LoggingContext): The context to activate.
        Returns:
            The context that was previously active
        """
        current = cls.current_context()

        if current is not context:
            current.stop()
            cls.thread_local.current_context = context
            context.start()
        return current

    def __enter__(self):
        """Enters this logging context into thread local storage"""
        old_context = self.set_current_context(self)
        if self.previous_context != old_context:
            logger.warn(
                "Expected previous context %r, found %r",
                self.previous_context,
                old_context,
            )
        self.alive = True

        return self

    def __exit__(self, type, value, traceback):
        """Restore the logging context in thread local storage to the state it
        was before this context was entered.
        Returns:
            None to avoid suppressing any exceptions that were thrown.
        """
        current = self.set_current_context(self.previous_context)
        if current is not self:
            if current is self.sentinel:
                logger.warning("Expected logging context %s was lost", self)
            else:
                logger.warning(
                    "Expected logging context %s but found %s", self, current
                )
        self.previous_context = None
        self.alive = False

        # if we have a parent, pass our CPU usage stats on
        if self.parent_context is not None and hasattr(
            self.parent_context, "_resource_usage"
        ):
            self.parent_context._resource_usage += self._resource_usage

            # reset them in case we get entered again
            self._resource_usage.reset()

    def copy_to(self, record):
        """Copy logging fields from this context to a log record or
        another LoggingContext
        """

        # 'request' is the only field we currently use in the logger, so that's
        # all we need to copy
        record.request = self.request

    def start(self):
        if threading.current_thread() is not self.main_thread:
            logger.warning("Started logcontext %s on different thread", self)
            return

        # If we haven't already started record the thread resource usage so
        # far
        if not self.usage_start:
            self.usage_start = get_thread_resource_usage()

    def stop(self):
        if threading.current_thread() is not self.main_thread:
            logger.warning("Stopped logcontext %s on different thread", self)
            return

        # When we stop, let's record the cpu used since we started
        if not self.usage_start:
            logger.warning("Called stop on logcontext %s without calling start", self)
            return

        utime_delta, stime_delta = self._get_cputime()
        self._resource_usage.ru_utime += utime_delta
        self._resource_usage.ru_stime += stime_delta

        self.usage_start = None

    def get_resource_usage(self):
        """Get resources used by this logcontext so far.

        Returns:
            ContextResourceUsage: a *copy* of the object tracking resource
                usage so far
        """
        # we always return a copy, for consistency
        res = self._resource_usage.copy()

        # If we are on the correct thread and we're currently running then we
        # can include resource usage so far.
        is_main_thread = threading.current_thread() is self.main_thread
        if self.alive and self.usage_start and is_main_thread:
            utime_delta, stime_delta = self._get_cputime()
            res.ru_utime += utime_delta
            res.ru_stime += stime_delta

        return res

    def _get_cputime(self):
        """Get the cpu usage time so far

        Returns: Tuple[float, float]: seconds in user mode, seconds in system mode
        """
        current = get_thread_resource_usage()

        utime_delta = current.ru_utime - self.usage_start.ru_utime
        stime_delta = current.ru_stime - self.usage_start.ru_stime

        # sanity check
        if utime_delta < 0:
            logger.error(
                "utime went backwards! %f < %f",
                current.ru_utime,
                self.usage_start.ru_utime,
            )
            utime_delta = 0

        if stime_delta < 0:
            logger.error(
                "stime went backwards! %f < %f",
                current.ru_stime,
                self.usage_start.ru_stime,
            )
            stime_delta = 0

        return utime_delta, stime_delta

    def add_database_transaction(self, duration_sec):
        if duration_sec < 0:
            raise ValueError("DB txn time can only be non-negative")
        self._resource_usage.db_txn_count += 1
        self._resource_usage.db_txn_duration_sec += duration_sec

    def add_database_scheduled(self, sched_sec):
        """Record a use of the database pool

        Args:
            sched_sec (float): number of seconds it took us to get a
                connection
        """
        if sched_sec < 0:
            raise ValueError("DB scheduling time can only be non-negative")
        self._resource_usage.db_sched_duration_sec += sched_sec

    def record_event_fetch(self, event_count):
        """Record a number of events being fetched from the db

        Args:
            event_count (int): number of events being fetched
        """
        self._resource_usage.evt_db_fetch_count += event_count


class LoggingContextFilter(logging.Filter):
    """Logging filter that adds values from the current logging context to each
    record.
    Args:
        **defaults: Default values to avoid formatters complaining about
            missing fields
    """

    def __init__(self, **defaults):
        self.defaults = defaults

    def filter(self, record):
        """Add each fields from the logging contexts to the record.
        Returns:
            True to include the record in the log output.
        """
        context = LoggingContext.current_context()
        for key, value in self.defaults.items():
            setattr(record, key, value)

        # context should never be None, but if it somehow ends up being, then
        # we end up in a death spiral of infinite loops, so let's check, for
        # robustness' sake.
        if context is not None:
            context.copy_to(record)

        return True


class PreserveLoggingContext(object):
    """Captures the current logging context and restores it when the scope is
    exited. Used to restore the context after a function using
    @defer.inlineCallbacks is resumed by a callback from the reactor."""

    __slots__ = ["current_context", "new_context", "has_parent"]

    def __init__(self, new_context=None):
        if new_context is None:
            new_context = LoggingContext.sentinel
        self.new_context = new_context

    def __enter__(self):
        """Captures the current logging context"""
        self.current_context = LoggingContext.set_current_context(self.new_context)

        if self.current_context:
            self.has_parent = self.current_context.previous_context is not None
            if not self.current_context.alive:
                logger.debug("Entering dead context: %s", self.current_context)

    def __exit__(self, type, value, traceback):
        """Restores the current logging context"""
        context = LoggingContext.set_current_context(self.current_context)

        if context != self.new_context:
            if context is LoggingContext.sentinel:
                logger.warning("Expected logging context %s was lost", self.new_context)
            else:
                logger.warning(
                    "Expected logging context %s but found %s",
                    self.new_context,
                    context,
                )

        if self.current_context is not LoggingContext.sentinel:
            if not self.current_context.alive:
                logger.debug("Restoring dead context: %s", self.current_context)


def nested_logging_context(suffix, parent_context=None):
    """Creates a new logging context as a child of another.

    The nested logging context will have a 'request' made up of the parent context's
    request, plus the given suffix.

    CPU/db usage stats will be added to the parent context's on exit.

    Normal usage looks like:

        with nested_logging_context(suffix):
            # ... do stuff

    Args:
        suffix (str): suffix to add to the parent context's 'request'.
        parent_context (LoggingContext|None): parent context. Will use the current context
            if None.

    Returns:
        LoggingContext: new logging context.
    """
    if parent_context is None:
        parent_context = LoggingContext.current_context()
    return LoggingContext(
        parent_context=parent_context, request=parent_context.request + "-" + suffix
    )


def preserve_fn(f):
    """Function decorator which wraps the function with run_in_background"""

    def g(*args, **kwargs):
        return run_in_background(f, *args, **kwargs)

    return g


def run_in_background(f, *args, **kwargs):
    """Calls a function, ensuring that the current context is restored after
    return from the function, and that the sentinel context is set once the
    deferred returned by the function completes.

    Useful for wrapping functions that return a deferred or coroutine, which you don't
    yield or await on (for instance because you want to pass it to
    deferred.gatherResults()).

    Note that if you completely discard the result, you should make sure that
    `f` doesn't raise any deferred exceptions, otherwise a scary-looking
    CRITICAL error about an unhandled error will be logged without much
    indication about where it came from.
    """
    current = LoggingContext.current_context()
    try:
        res = f(*args, **kwargs)
    except:  # noqa: E722
        # the assumption here is that the caller doesn't want to be disturbed
        # by synchronous exceptions, so let's turn them into Failures.
        return defer.fail()

    if isinstance(res, types.CoroutineType):
        res = defer.ensureDeferred(res)

    if not isinstance(res, defer.Deferred):
        return res

    if res.called and not res.paused:
        # The function should have maintained the logcontext, so we can
        # optimise out the messing about
        return res

    # The function may have reset the context before returning, so
    # we need to restore it now.
    ctx = LoggingContext.set_current_context(current)

    # The original context will be restored when the deferred
    # completes, but there is nothing waiting for it, so it will
    # get leaked into the reactor or some other function which
    # wasn't expecting it. We therefore need to reset the context
    # here.
    #
    # (If this feels asymmetric, consider it this way: we are
    # effectively forking a new thread of execution. We are
    # probably currently within a ``with LoggingContext()`` block,
    # which is supposed to have a single entry and exit point. But
    # by spawning off another deferred, we are effectively
    # adding a new exit point.)
    res.addBoth(_set_context_cb, ctx)
    return res


def make_deferred_yieldable(deferred):
    """Given a deferred, make it follow the Synapse logcontext rules:

    If the deferred has completed (or is not actually a Deferred), essentially
    does nothing (just returns another completed deferred with the
    result/failure).

    If the deferred has not yet completed, resets the logcontext before
    returning a deferred. Then, when the deferred completes, restores the
    current logcontext before running callbacks/errbacks.

    (This is more-or-less the opposite operation to run_in_background.)
    """
    if not isinstance(deferred, defer.Deferred):
        return deferred

    if deferred.called and not deferred.paused:
        # it looks like this deferred is ready to run any callbacks we give it
        # immediately. We may as well optimise out the logcontext faffery.
        return deferred

    # ok, we can't be sure that a yield won't block, so let's reset the
    # logcontext, and add a callback to the deferred to restore it.
    prev_context = LoggingContext.set_current_context(LoggingContext.sentinel)
    deferred.addBoth(_set_context_cb, prev_context)
    return deferred


def _set_context_cb(result, context):
    """A callback function which just sets the logging context"""
    LoggingContext.set_current_context(context)
    return result


def defer_to_thread(reactor, f, *args, **kwargs):
    """
    Calls the function `f` using a thread from the reactor's default threadpool and
    returns the result as a Deferred.

    Creates a new logcontext for `f`, which is created as a child of the current
    logcontext (so its CPU usage metrics will get attributed to the current
    logcontext). `f` should preserve the logcontext it is given.

    The result deferred follows the Synapse logcontext rules: you should `yield`
    on it.

    Args:
        reactor (twisted.internet.base.ReactorBase): The reactor in whose main thread
            the Deferred will be invoked, and whose threadpool we should use for the
            function.

            Normally this will be hs.get_reactor().

        f (callable): The function to call.

        args: positional arguments to pass to f.

        kwargs: keyword arguments to pass to f.

    Returns:
        Deferred: A Deferred which fires a callback with the result of `f`, or an
            errback if `f` throws an exception.
    """
    return defer_to_threadpool(reactor, reactor.getThreadPool(), f, *args, **kwargs)


def defer_to_threadpool(reactor, threadpool, f, *args, **kwargs):
    """
    A wrapper for twisted.internet.threads.deferToThreadpool, which handles
    logcontexts correctly.

    Calls the function `f` using a thread from the given threadpool and returns
    the result as a Deferred.

    Creates a new logcontext for `f`, which is created as a child of the current
    logcontext (so its CPU usage metrics will get attributed to the current
    logcontext). `f` should preserve the logcontext it is given.

    The result deferred follows the Synapse logcontext rules: you should `yield`
    on it.

    Args:
        reactor (twisted.internet.base.ReactorBase): The reactor in whose main thread
            the Deferred will be invoked. Normally this will be hs.get_reactor().

        threadpool (twisted.python.threadpool.ThreadPool): The threadpool to use for
            running `f`. Normally this will be hs.get_reactor().getThreadPool().

        f (callable): The function to call.

        args: positional arguments to pass to f.

        kwargs: keyword arguments to pass to f.

    Returns:
        Deferred: A Deferred which fires a callback with the result of `f`, or an
            errback if `f` throws an exception.
    """
    logcontext = LoggingContext.current_context()

    def g():
        with LoggingContext(parent_context=logcontext):
            return f(*args, **kwargs)

    return make_deferred_yieldable(threads.deferToThreadPool(reactor, threadpool, g))
