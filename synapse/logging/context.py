# Copyright 2014-2016 OpenMarket Ltd
# Copyright 2019 The Matrix.org Foundation C.I.C.
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
import typing
import warnings
from types import TracebackType
from typing import (
    TYPE_CHECKING,
    Awaitable,
    Callable,
    Optional,
    Tuple,
    Type,
    TypeVar,
    Union,
    overload,
)

import attr
from typing_extensions import Literal, ParamSpec

from twisted.internet import defer, threads
from twisted.python.threadpool import ThreadPool

if TYPE_CHECKING:
    from synapse.logging.scopecontextmanager import _LogContextScope
    from synapse.types import ISynapseReactor

logger = logging.getLogger(__name__)

try:
    import resource

    # Python doesn't ship with a definition of RUSAGE_THREAD but it's defined
    # to be 1 on linux so we hard code it.
    RUSAGE_THREAD = 1

    # If the system doesn't support RUSAGE_THREAD then this should throw an
    # exception.
    resource.getrusage(RUSAGE_THREAD)

    is_thread_resource_usage_supported = True

    def get_thread_resource_usage() -> "Optional[resource.struct_rusage]":
        return resource.getrusage(RUSAGE_THREAD)

except Exception:
    # If the system doesn't support resource.getrusage(RUSAGE_THREAD) then we
    # won't track resource usage.
    is_thread_resource_usage_supported = False

    def get_thread_resource_usage() -> "Optional[resource.struct_rusage]":
        return None


# a hook which can be set during testing to assert that we aren't abusing logcontexts.
def logcontext_error(msg: str) -> None:
    logger.warning(msg)


# get an id for the current thread.
#
# threading.get_ident doesn't actually return an OS-level tid, and annoyingly,
# on Linux it actually returns the same value either side of a fork() call. However
# we only fork in one place, so it's not worth the hoop-jumping to get a real tid.
#
get_thread_id = threading.get_ident


class ContextResourceUsage:
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

    def __init__(self, copy_from: "Optional[ContextResourceUsage]" = None) -> None:
        """Create a new ContextResourceUsage

        Args:
            copy_from (ContextResourceUsage|None): if not None, an object to
                copy stats from
        """
        if copy_from is None:
            self.reset()
        else:
            # FIXME: mypy can't infer the types set via reset() above, so specify explicitly for now
            self.ru_utime: float = copy_from.ru_utime
            self.ru_stime: float = copy_from.ru_stime
            self.db_txn_count: int = copy_from.db_txn_count

            self.db_txn_duration_sec: float = copy_from.db_txn_duration_sec
            self.db_sched_duration_sec: float = copy_from.db_sched_duration_sec
            self.evt_db_fetch_count: int = copy_from.evt_db_fetch_count

    def copy(self) -> "ContextResourceUsage":
        return ContextResourceUsage(copy_from=self)

    def reset(self) -> None:
        self.ru_stime = 0.0
        self.ru_utime = 0.0
        self.db_txn_count = 0

        self.db_txn_duration_sec = 0.0
        self.db_sched_duration_sec = 0.0
        self.evt_db_fetch_count = 0

    def __repr__(self) -> str:
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

    def __iadd__(self, other: "ContextResourceUsage") -> "ContextResourceUsage":
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

    def __isub__(self, other: "ContextResourceUsage") -> "ContextResourceUsage":
        self.ru_utime -= other.ru_utime
        self.ru_stime -= other.ru_stime
        self.db_txn_count -= other.db_txn_count
        self.db_txn_duration_sec -= other.db_txn_duration_sec
        self.db_sched_duration_sec -= other.db_sched_duration_sec
        self.evt_db_fetch_count -= other.evt_db_fetch_count
        return self

    def __add__(self, other: "ContextResourceUsage") -> "ContextResourceUsage":
        res = ContextResourceUsage(copy_from=self)
        res += other
        return res

    def __sub__(self, other: "ContextResourceUsage") -> "ContextResourceUsage":
        res = ContextResourceUsage(copy_from=self)
        res -= other
        return res


@attr.s(slots=True, auto_attribs=True)
class ContextRequest:
    """
    A bundle of attributes from the SynapseRequest object.

    This exists to:

    * Avoid a cycle between LoggingContext and SynapseRequest.
    * Be a single variable that can be passed from parent LoggingContexts to
      their children.
    """

    request_id: str
    ip_address: str
    site_tag: str
    requester: Optional[str]
    authenticated_entity: Optional[str]
    method: str
    url: str
    protocol: str
    user_agent: str


LoggingContextOrSentinel = Union["LoggingContext", "_Sentinel"]


class _Sentinel:
    """Sentinel to represent the root context"""

    __slots__ = ["previous_context", "finished", "request", "scope", "tag"]

    def __init__(self) -> None:
        # Minimal set for compatibility with LoggingContext
        self.previous_context = None
        self.finished = False
        self.request = None
        self.scope = None
        self.tag = None

    def __str__(self) -> str:
        return "sentinel"

    def start(self, rusage: "Optional[resource.struct_rusage]") -> None:
        pass

    def stop(self, rusage: "Optional[resource.struct_rusage]") -> None:
        pass

    def add_database_transaction(self, duration_sec: float) -> None:
        pass

    def add_database_scheduled(self, sched_sec: float) -> None:
        pass

    def record_event_fetch(self, event_count: int) -> None:
        pass

    def __bool__(self) -> Literal[False]:
        return False


SENTINEL_CONTEXT = _Sentinel()


class LoggingContext:
    """Additional context for log formatting. Contexts are scoped within a
    "with" block.

    If a parent is given when creating a new context, then:
        - logging fields are copied from the parent to the new context on entry
        - when the new context exits, the cpu usage stats are copied from the
          child to the parent

    Args:
        name: Name for the context for logging. If this is omitted, it is
           inherited from the parent context.
        parent_context (LoggingContext|None): The parent of the new context
    """

    __slots__ = [
        "previous_context",
        "name",
        "parent_context",
        "_resource_usage",
        "usage_start",
        "main_thread",
        "finished",
        "request",
        "tag",
        "scope",
    ]

    def __init__(
        self,
        name: Optional[str] = None,
        parent_context: "Optional[LoggingContext]" = None,
        request: Optional[ContextRequest] = None,
    ) -> None:
        self.previous_context = current_context()

        # track the resources used by this context so far
        self._resource_usage = ContextResourceUsage()

        # The thread resource usage when the logcontext became active. None
        # if the context is not currently active.
        self.usage_start: Optional[resource.struct_rusage] = None

        self.main_thread = get_thread_id()
        self.request = None
        self.tag = ""
        self.scope: Optional["_LogContextScope"] = None

        # keep track of whether we have hit the __exit__ block for this context
        # (suggesting that the the thing that created the context thinks it should
        # be finished, and that re-activating it would suggest an error).
        self.finished = False

        self.parent_context = parent_context

        if self.parent_context is not None:
            # we track the current request_id
            self.request = self.parent_context.request

            # we also track the current scope:
            self.scope = self.parent_context.scope

        if request is not None:
            # the request param overrides the request from the parent context
            self.request = request

        # if we don't have a `name`, but do have a parent context, use its name.
        if self.parent_context and name is None:
            name = str(self.parent_context)
        if name is None:
            raise ValueError(
                "LoggingContext must be given either a name or a parent context"
            )
        self.name = name

    def __str__(self) -> str:
        return self.name

    @classmethod
    def current_context(cls) -> LoggingContextOrSentinel:
        """Get the current logging context from thread local storage

        This exists for backwards compatibility. ``current_context()`` should be
        called directly.

        Returns:
            LoggingContext: the current logging context
        """
        warnings.warn(
            "synapse.logging.context.LoggingContext.current_context() is deprecated "
            "in favor of synapse.logging.context.current_context().",
            DeprecationWarning,
            stacklevel=2,
        )
        return current_context()

    @classmethod
    def set_current_context(
        cls, context: LoggingContextOrSentinel
    ) -> LoggingContextOrSentinel:
        """Set the current logging context in thread local storage

        This exists for backwards compatibility. ``set_current_context()`` should be
        called directly.

        Args:
            context(LoggingContext): The context to activate.
        Returns:
            The context that was previously active
        """
        warnings.warn(
            "synapse.logging.context.LoggingContext.set_current_context() is deprecated "
            "in favor of synapse.logging.context.set_current_context().",
            DeprecationWarning,
            stacklevel=2,
        )
        return set_current_context(context)

    def __enter__(self) -> "LoggingContext":
        """Enters this logging context into thread local storage"""
        old_context = set_current_context(self)
        if self.previous_context != old_context:
            logcontext_error(
                "Expected previous context %r, found %r"
                % (
                    self.previous_context,
                    old_context,
                )
            )
        return self

    def __exit__(
        self,
        type: Optional[Type[BaseException]],
        value: Optional[BaseException],
        traceback: Optional[TracebackType],
    ) -> None:
        """Restore the logging context in thread local storage to the state it
        was before this context was entered.
        Returns:
            None to avoid suppressing any exceptions that were thrown.
        """
        current = set_current_context(self.previous_context)
        if current is not self:
            if current is SENTINEL_CONTEXT:
                logcontext_error("Expected logging context %s was lost" % (self,))
            else:
                logcontext_error(
                    "Expected logging context %s but found %s" % (self, current)
                )

        # the fact that we are here suggests that the caller thinks that everything
        # is done and dusted for this logcontext, and further activity will not get
        # recorded against the correct metrics.
        self.finished = True

    def start(self, rusage: "Optional[resource.struct_rusage]") -> None:
        """
        Record that this logcontext is currently running.

        This should not be called directly: use set_current_context

        Args:
            rusage: the resources used by the current thread, at the point of
                switching to this logcontext. May be None if this platform doesn't
                support getrusuage.
        """
        if get_thread_id() != self.main_thread:
            logcontext_error("Started logcontext %s on different thread" % (self,))
            return

        if self.finished:
            logcontext_error("Re-starting finished log context %s" % (self,))

        # If we haven't already started record the thread resource usage so
        # far
        if self.usage_start:
            logcontext_error("Re-starting already-active log context %s" % (self,))
        else:
            self.usage_start = rusage

    def stop(self, rusage: "Optional[resource.struct_rusage]") -> None:
        """
        Record that this logcontext is no longer running.

        This should not be called directly: use set_current_context

        Args:
            rusage: the resources used by the current thread, at the point of
                switching away from this logcontext. May be None if this platform
                doesn't support getrusuage.
        """

        try:
            if get_thread_id() != self.main_thread:
                logcontext_error("Stopped logcontext %s on different thread" % (self,))
                return

            if not rusage:
                return

            # Record the cpu used since we started
            if not self.usage_start:
                logcontext_error(
                    "Called stop on logcontext %s without recording a start rusage"
                    % (self,)
                )
                return

            utime_delta, stime_delta = self._get_cputime(rusage)
            self.add_cputime(utime_delta, stime_delta)
        finally:
            self.usage_start = None

    def get_resource_usage(self) -> ContextResourceUsage:
        """Get resources used by this logcontext so far.

        Returns:
            ContextResourceUsage: a *copy* of the object tracking resource
                usage so far
        """
        # we always return a copy, for consistency
        res = self._resource_usage.copy()

        # If we are on the correct thread and we're currently running then we
        # can include resource usage so far.
        is_main_thread = get_thread_id() == self.main_thread
        if self.usage_start and is_main_thread:
            rusage = get_thread_resource_usage()
            assert rusage is not None
            utime_delta, stime_delta = self._get_cputime(rusage)
            res.ru_utime += utime_delta
            res.ru_stime += stime_delta

        return res

    def _get_cputime(self, current: "resource.struct_rusage") -> Tuple[float, float]:
        """Get the cpu usage time between start() and the given rusage

        Args:
            rusage: the current resource usage

        Returns: Tuple[float, float]: seconds in user mode, seconds in system mode
        """
        assert self.usage_start is not None

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

    def add_cputime(self, utime_delta: float, stime_delta: float) -> None:
        """Update the CPU time usage of this context (and any parents, recursively).

        Args:
            utime_delta: additional user time, in seconds, spent in this context.
            stime_delta: additional system time, in seconds, spent in this context.
        """
        self._resource_usage.ru_utime += utime_delta
        self._resource_usage.ru_stime += stime_delta
        if self.parent_context:
            self.parent_context.add_cputime(utime_delta, stime_delta)

    def add_database_transaction(self, duration_sec: float) -> None:
        """Record the use of a database transaction and the length of time it took.

        Args:
            duration_sec: The number of seconds the database transaction took.
        """
        if duration_sec < 0:
            raise ValueError("DB txn time can only be non-negative")
        self._resource_usage.db_txn_count += 1
        self._resource_usage.db_txn_duration_sec += duration_sec
        if self.parent_context:
            self.parent_context.add_database_transaction(duration_sec)

    def add_database_scheduled(self, sched_sec: float) -> None:
        """Record a use of the database pool

        Args:
            sched_sec: number of seconds it took us to get a connection
        """
        if sched_sec < 0:
            raise ValueError("DB scheduling time can only be non-negative")
        self._resource_usage.db_sched_duration_sec += sched_sec
        if self.parent_context:
            self.parent_context.add_database_scheduled(sched_sec)

    def record_event_fetch(self, event_count: int) -> None:
        """Record a number of events being fetched from the db

        Args:
            event_count: number of events being fetched
        """
        self._resource_usage.evt_db_fetch_count += event_count
        if self.parent_context:
            self.parent_context.record_event_fetch(event_count)


class LoggingContextFilter(logging.Filter):
    """Logging filter that adds values from the current logging context to each
    record.
    """

    def __init__(self, request: str = ""):
        self._default_request = request

    def filter(self, record: logging.LogRecord) -> Literal[True]:
        """Add each fields from the logging contexts to the record.
        Returns:
            True to include the record in the log output.
        """
        context = current_context()
        record.request = self._default_request

        # context should never be None, but if it somehow ends up being, then
        # we end up in a death spiral of infinite loops, so let's check, for
        # robustness' sake.
        if context is not None:
            # Logging is interested in the request ID. Note that for backwards
            # compatibility this is stored as the "request" on the record.
            record.request = str(context)

            # Add some data from the HTTP request.
            request = context.request
            if request is None:
                return True

            record.ip_address = request.ip_address
            record.site_tag = request.site_tag
            record.requester = request.requester
            record.authenticated_entity = request.authenticated_entity
            record.method = request.method
            record.url = request.url
            record.protocol = request.protocol
            record.user_agent = request.user_agent

        return True


class PreserveLoggingContext:
    """Context manager which replaces the logging context

    The previous logging context is restored on exit."""

    __slots__ = ["_old_context", "_new_context"]

    def __init__(
        self, new_context: LoggingContextOrSentinel = SENTINEL_CONTEXT
    ) -> None:
        self._new_context = new_context

    def __enter__(self) -> None:
        self._old_context = set_current_context(self._new_context)

    def __exit__(
        self,
        type: Optional[Type[BaseException]],
        value: Optional[BaseException],
        traceback: Optional[TracebackType],
    ) -> None:
        context = set_current_context(self._old_context)

        if context != self._new_context:
            if not context:
                logcontext_error(
                    "Expected logging context %s was lost" % (self._new_context,)
                )
            else:
                logcontext_error(
                    "Expected logging context %s but found %s"
                    % (
                        self._new_context,
                        context,
                    )
                )


_thread_local = threading.local()
_thread_local.current_context = SENTINEL_CONTEXT


def current_context() -> LoggingContextOrSentinel:
    """Get the current logging context from thread local storage"""
    return getattr(_thread_local, "current_context", SENTINEL_CONTEXT)


def set_current_context(context: LoggingContextOrSentinel) -> LoggingContextOrSentinel:
    """Set the current logging context in thread local storage
    Args:
        context(LoggingContext): The context to activate.
    Returns:
        The context that was previously active
    """
    # everything blows up if we allow current_context to be set to None, so sanity-check
    # that now.
    if context is None:
        raise TypeError("'context' argument may not be None")

    current = current_context()

    if current is not context:
        rusage = get_thread_resource_usage()
        current.stop(rusage)
        _thread_local.current_context = context
        context.start(rusage)

    return current


def nested_logging_context(suffix: str) -> LoggingContext:
    """Creates a new logging context as a child of another.

    The nested logging context will have a 'name' made up of the parent context's
    name, plus the given suffix.

    CPU/db usage stats will be added to the parent context's on exit.

    Normal usage looks like:

        with nested_logging_context(suffix):
            # ... do stuff

    Args:
        suffix: suffix to add to the parent context's 'name'.

    Returns:
        LoggingContext: new logging context.
    """
    curr_context = current_context()
    if not curr_context:
        logger.warning(
            "Starting nested logging context from sentinel context: metrics will be lost"
        )
        parent_context = None
    else:
        assert isinstance(curr_context, LoggingContext)
        parent_context = curr_context
    prefix = str(curr_context)
    return LoggingContext(
        prefix + "-" + suffix,
        parent_context=parent_context,
    )


P = ParamSpec("P")
R = TypeVar("R")


async def _unwrap_awaitable(awaitable: Awaitable[R]) -> R:
    """Unwraps an arbitrary awaitable by awaiting it."""
    return await awaitable


@overload
def preserve_fn(  # type: ignore[misc]
    f: Callable[P, Awaitable[R]],
) -> Callable[P, "defer.Deferred[R]"]:
    # The `type: ignore[misc]` above suppresses
    # "Overloaded function signatures 1 and 2 overlap with incompatible return types"
    ...


@overload
def preserve_fn(f: Callable[P, R]) -> Callable[P, "defer.Deferred[R]"]:
    ...


def preserve_fn(
    f: Union[
        Callable[P, R],
        Callable[P, Awaitable[R]],
    ]
) -> Callable[P, "defer.Deferred[R]"]:
    """Function decorator which wraps the function with run_in_background"""

    def g(*args: P.args, **kwargs: P.kwargs) -> "defer.Deferred[R]":
        return run_in_background(f, *args, **kwargs)

    return g


@overload
def run_in_background(  # type: ignore[misc]
    f: Callable[P, Awaitable[R]], *args: P.args, **kwargs: P.kwargs
) -> "defer.Deferred[R]":
    # The `type: ignore[misc]` above suppresses
    # "Overloaded function signatures 1 and 2 overlap with incompatible return types"
    ...


@overload
def run_in_background(
    f: Callable[P, R], *args: P.args, **kwargs: P.kwargs
) -> "defer.Deferred[R]":
    ...


def run_in_background(  # type: ignore[misc]
    # The `type: ignore[misc]` above suppresses
    # "Overloaded function implementation does not accept all possible arguments of signature 1"
    # "Overloaded function implementation does not accept all possible arguments of signature 2"
    # which seems like a bug in mypy.
    f: Union[
        Callable[P, R],
        Callable[P, Awaitable[R]],
    ],
    *args: P.args,
    **kwargs: P.kwargs,
) -> "defer.Deferred[R]":
    """Calls a function, ensuring that the current context is restored after
    return from the function, and that the sentinel context is set once the
    deferred returned by the function completes.

    Useful for wrapping functions that return a deferred or coroutine, which you don't
    yield or await on (for instance because you want to pass it to
    deferred.gatherResults()).

    If f returns a Coroutine object, it will be wrapped into a Deferred (which will have
    the side effect of executing the coroutine).

    Note that if you completely discard the result, you should make sure that
    `f` doesn't raise any deferred exceptions, otherwise a scary-looking
    CRITICAL error about an unhandled error will be logged without much
    indication about where it came from.
    """
    current = current_context()
    try:
        res = f(*args, **kwargs)
    except Exception:
        # the assumption here is that the caller doesn't want to be disturbed
        # by synchronous exceptions, so let's turn them into Failures.
        return defer.fail()

    # `res` may be a coroutine, `Deferred`, some other kind of awaitable, or a plain
    # value. Convert it to a `Deferred`.
    if isinstance(res, typing.Coroutine):
        # Wrap the coroutine in a `Deferred`.
        res = defer.ensureDeferred(res)
    elif isinstance(res, defer.Deferred):
        pass
    elif isinstance(res, Awaitable):
        # `res` is probably some kind of completed awaitable, such as a `DoneAwaitable`
        # or `Future` from `make_awaitable`.
        res = defer.ensureDeferred(_unwrap_awaitable(res))
    else:
        # `res` is a plain value. Wrap it in a `Deferred`.
        res = defer.succeed(res)

    if res.called and not res.paused:
        # The function should have maintained the logcontext, so we can
        # optimise out the messing about
        return res

    # The function may have reset the context before returning, so
    # we need to restore it now.
    ctx = set_current_context(current)

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


T = TypeVar("T")


def make_deferred_yieldable(deferred: "defer.Deferred[T]") -> "defer.Deferred[T]":
    """Given a deferred, make it follow the Synapse logcontext rules:

    If the deferred has completed, essentially does nothing (just returns another
    completed deferred with the result/failure).

    If the deferred has not yet completed, resets the logcontext before
    returning a deferred. Then, when the deferred completes, restores the
    current logcontext before running callbacks/errbacks.

    (This is more-or-less the opposite operation to run_in_background.)
    """
    if deferred.called and not deferred.paused:
        # it looks like this deferred is ready to run any callbacks we give it
        # immediately. We may as well optimise out the logcontext faffery.
        return deferred

    # ok, we can't be sure that a yield won't block, so let's reset the
    # logcontext, and add a callback to the deferred to restore it.
    prev_context = set_current_context(SENTINEL_CONTEXT)
    deferred.addBoth(_set_context_cb, prev_context)
    return deferred


ResultT = TypeVar("ResultT")


def _set_context_cb(result: ResultT, context: LoggingContext) -> ResultT:
    """A callback function which just sets the logging context"""
    set_current_context(context)
    return result


def defer_to_thread(
    reactor: "ISynapseReactor", f: Callable[P, R], *args: P.args, **kwargs: P.kwargs
) -> "defer.Deferred[R]":
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


def defer_to_threadpool(
    reactor: "ISynapseReactor",
    threadpool: ThreadPool,
    f: Callable[P, R],
    *args: P.args,
    **kwargs: P.kwargs,
) -> "defer.Deferred[R]":
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
    curr_context = current_context()
    if not curr_context:
        logger.warning(
            "Calling defer_to_threadpool from sentinel context: metrics will be lost"
        )
        parent_context = None
    else:
        assert isinstance(curr_context, LoggingContext)
        parent_context = curr_context

    def g() -> R:
        with LoggingContext(str(curr_context), parent_context=parent_context):
            return f(*args, **kwargs)

    return make_deferred_yieldable(threads.deferToThreadPool(reactor, threadpool, g))
