# Copyright 2014-2016 OpenMarket Ltd
# Copyright 2018 New Vector Ltd
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

import collections
import inspect
import itertools
import logging
from contextlib import contextmanager
from typing import (
    Any,
    Awaitable,
    Callable,
    Dict,
    Hashable,
    Iterable,
    List,
    Optional,
    Set,
    TypeVar,
    Union,
)

import attr
from typing_extensions import ContextManager

from twisted.internet import defer
from twisted.internet.defer import CancelledError
from twisted.internet.interfaces import IReactorTime
from twisted.python import failure

from synapse.logging.context import (
    PreserveLoggingContext,
    make_deferred_yieldable,
    run_in_background,
)
from synapse.util import Clock, unwrapFirstError

logger = logging.getLogger(__name__)


class ObservableDeferred:
    """Wraps a deferred object so that we can add observer deferreds. These
    observer deferreds do not affect the callback chain of the original
    deferred.

    If consumeErrors is true errors will be captured from the origin deferred.

    Cancelling or otherwise resolving an observer will not affect the original
    ObservableDeferred.

    NB that it does not attempt to do anything with logcontexts; in general
    you should probably make_deferred_yieldable the deferreds
    returned by `observe`, and ensure that the original deferred runs its
    callbacks in the sentinel logcontext.
    """

    __slots__ = ["_deferred", "_observers", "_result"]

    def __init__(self, deferred: defer.Deferred, consumeErrors: bool = False):
        object.__setattr__(self, "_deferred", deferred)
        object.__setattr__(self, "_result", None)
        object.__setattr__(self, "_observers", set())

        def callback(r):
            object.__setattr__(self, "_result", (True, r))
            while self._observers:
                observer = self._observers.pop()
                try:
                    observer.callback(r)
                except Exception as e:
                    logger.exception(
                        "%r threw an exception on .callback(%r), ignoring...",
                        observer,
                        r,
                        exc_info=e,
                    )
            return r

        def errback(f):
            object.__setattr__(self, "_result", (False, f))
            while self._observers:
                # This is a little bit of magic to correctly propagate stack
                # traces when we `await` on one of the observer deferreds.
                f.value.__failure__ = f

                observer = self._observers.pop()
                try:
                    observer.errback(f)
                except Exception as e:
                    logger.exception(
                        "%r threw an exception on .errback(%r), ignoring...",
                        observer,
                        f,
                        exc_info=e,
                    )

            if consumeErrors:
                return None
            else:
                return f

        deferred.addCallbacks(callback, errback)

    def observe(self) -> defer.Deferred:
        """Observe the underlying deferred.

        This returns a brand new deferred that is resolved when the underlying
        deferred is resolved. Interacting with the returned deferred does not
        effect the underlying deferred.
        """
        if not self._result:
            d = defer.Deferred()

            def remove(r):
                self._observers.discard(d)
                return r

            d.addBoth(remove)

            self._observers.add(d)
            return d
        else:
            success, res = self._result
            return defer.succeed(res) if success else defer.fail(res)

    def observers(self) -> List[defer.Deferred]:
        return self._observers

    def has_called(self) -> bool:
        return self._result is not None

    def has_succeeded(self) -> bool:
        return self._result is not None and self._result[0] is True

    def get_result(self) -> Any:
        return self._result[1]

    def __getattr__(self, name: str) -> Any:
        return getattr(self._deferred, name)

    def __setattr__(self, name: str, value: Any) -> None:
        setattr(self._deferred, name, value)

    def __repr__(self) -> str:
        return "<ObservableDeferred object at %s, result=%r, _deferred=%r>" % (
            id(self),
            self._result,
            self._deferred,
        )


T = TypeVar("T")


def concurrently_execute(
    func: Callable[[T], Any], args: Iterable[T], limit: int
) -> defer.Deferred:
    """Executes the function with each argument concurrently while limiting
    the number of concurrent executions.

    Args:
        func: Function to execute, should return a deferred or coroutine.
        args: List of arguments to pass to func, each invocation of func
            gets a single argument.
        limit: Maximum number of conccurent executions.

    Returns:
        Deferred: Resolved when all function invocations have finished.
    """
    it = iter(args)

    async def _concurrently_execute_inner(value: T) -> None:
        try:
            while True:
                await maybe_awaitable(func(value))
                value = next(it)
        except StopIteration:
            pass

    # We use `itertools.islice` to handle the case where the number of args is
    # less than the limit, avoiding needlessly spawning unnecessary background
    # tasks.
    return make_deferred_yieldable(
        defer.gatherResults(
            [
                run_in_background(_concurrently_execute_inner, value)
                for value in itertools.islice(it, limit)
            ],
            consumeErrors=True,
        )
    ).addErrback(unwrapFirstError)


def yieldable_gather_results(
    func: Callable, iter: Iterable, *args: Any, **kwargs: Any
) -> defer.Deferred:
    """Executes the function with each argument concurrently.

    Args:
        func: Function to execute that returns a Deferred
        iter: An iterable that yields items that get passed as the first
            argument to the function
        *args: Arguments to be passed to each call to func
        **kwargs: Keyword arguments to be passed to each call to func

    Returns
        Deferred[list]: Resolved when all functions have been invoked, or errors if
        one of the function calls fails.
    """
    return make_deferred_yieldable(
        defer.gatherResults(
            [run_in_background(func, item, *args, **kwargs) for item in iter],
            consumeErrors=True,
        )
    ).addErrback(unwrapFirstError)


@attr.s(slots=True)
class _LinearizerEntry:
    # The number of things executing.
    count = attr.ib(type=int)
    # Deferreds for the things blocked from executing.
    deferreds = attr.ib(type=collections.OrderedDict)


class Linearizer:
    """Limits concurrent access to resources based on a key. Useful to ensure
    only a few things happen at a time on a given resource.

    Example:

        with await limiter.queue("test_key"):
            # do some work.

    """

    def __init__(
        self,
        name: Optional[str] = None,
        max_count: int = 1,
        clock: Optional[Clock] = None,
    ):
        """
        Args:
            max_count: The maximum number of concurrent accesses
        """
        if name is None:
            self.name = id(self)  # type: Union[str, int]
        else:
            self.name = name

        if not clock:
            from twisted.internet import reactor

            clock = Clock(reactor)
        self._clock = clock
        self.max_count = max_count

        # key_to_defer is a map from the key to a _LinearizerEntry.
        self.key_to_defer = {}  # type: Dict[Hashable, _LinearizerEntry]

    def is_queued(self, key: Hashable) -> bool:
        """Checks whether there is a process queued up waiting"""
        entry = self.key_to_defer.get(key)
        if not entry:
            # No entry so nothing is waiting.
            return False

        # There are waiting deferreds only in the OrderedDict of deferreds is
        # non-empty.
        return bool(entry.deferreds)

    def queue(self, key: Hashable) -> defer.Deferred:
        # we avoid doing defer.inlineCallbacks here, so that cancellation works correctly.
        # (https://twistedmatrix.com/trac/ticket/4632 meant that cancellations were not
        # propagated inside inlineCallbacks until Twisted 18.7)
        entry = self.key_to_defer.setdefault(
            key, _LinearizerEntry(0, collections.OrderedDict())
        )

        # If the number of things executing is greater than the maximum
        # then add a deferred to the list of blocked items
        # When one of the things currently executing finishes it will callback
        # this item so that it can continue executing.
        if entry.count >= self.max_count:
            res = self._await_lock(key)
        else:
            logger.debug(
                "Acquired uncontended linearizer lock %r for key %r", self.name, key
            )
            entry.count += 1
            res = defer.succeed(None)

        # once we successfully get the lock, we need to return a context manager which
        # will release the lock.

        @contextmanager
        def _ctx_manager(_):
            try:
                yield
            finally:
                logger.debug("Releasing linearizer lock %r for key %r", self.name, key)

                # We've finished executing so check if there are any things
                # blocked waiting to execute and start one of them
                entry.count -= 1

                if entry.deferreds:
                    (next_def, _) = entry.deferreds.popitem(last=False)

                    # we need to run the next thing in the sentinel context.
                    with PreserveLoggingContext():
                        next_def.callback(None)
                elif entry.count == 0:
                    # We were the last thing for this key: remove it from the
                    # map.
                    del self.key_to_defer[key]

        res.addCallback(_ctx_manager)
        return res

    def _await_lock(self, key: Hashable) -> defer.Deferred:
        """Helper for queue: adds a deferred to the queue

        Assumes that we've already checked that we've reached the limit of the number
        of lock-holders we allow. Creates a new deferred which is added to the list, and
        adds some management around cancellations.

        Returns the deferred, which will callback once we have secured the lock.

        """
        entry = self.key_to_defer[key]

        logger.debug("Waiting to acquire linearizer lock %r for key %r", self.name, key)

        new_defer = make_deferred_yieldable(defer.Deferred())
        entry.deferreds[new_defer] = 1

        def cb(_r):
            logger.debug("Acquired linearizer lock %r for key %r", self.name, key)
            entry.count += 1

            # if the code holding the lock completes synchronously, then it
            # will recursively run the next claimant on the list. That can
            # relatively rapidly lead to stack exhaustion. This is essentially
            # the same problem as http://twistedmatrix.com/trac/ticket/9304.
            #
            # In order to break the cycle, we add a cheeky sleep(0) here to
            # ensure that we fall back to the reactor between each iteration.
            #
            # (This needs to happen while we hold the lock, and the context manager's exit
            # code must be synchronous, so this is the only sensible place.)
            return self._clock.sleep(0)

        def eb(e):
            logger.info("defer %r got err %r", new_defer, e)
            if isinstance(e, CancelledError):
                logger.debug(
                    "Cancelling wait for linearizer lock %r for key %r", self.name, key
                )

            else:
                logger.warning(
                    "Unexpected exception waiting for linearizer lock %r for key %r",
                    self.name,
                    key,
                )

            # we just have to take ourselves back out of the queue.
            del entry.deferreds[new_defer]
            return e

        new_defer.addCallbacks(cb, eb)
        return new_defer


class ReadWriteLock:
    """An async read write lock.

    Example:

        with await read_write_lock.read("test_key"):
            # do some work
    """

    # IMPLEMENTATION NOTES
    #
    # We track the most recent queued reader and writer deferreds (which get
    # resolved when they release the lock).
    #
    # Read: We know its safe to acquire a read lock when the latest writer has
    # been resolved. The new reader is appended to the list of latest readers.
    #
    # Write: We know its safe to acquire the write lock when both the latest
    # writers and readers have been resolved. The new writer replaces the latest
    # writer.

    def __init__(self):
        # Latest readers queued
        self.key_to_current_readers = {}  # type: Dict[str, Set[defer.Deferred]]

        # Latest writer queued
        self.key_to_current_writer = {}  # type: Dict[str, defer.Deferred]

    async def read(self, key: str) -> ContextManager:
        new_defer = defer.Deferred()

        curr_readers = self.key_to_current_readers.setdefault(key, set())
        curr_writer = self.key_to_current_writer.get(key, None)

        curr_readers.add(new_defer)

        # We wait for the latest writer to finish writing. We can safely ignore
        # any existing readers... as they're readers.
        if curr_writer:
            await make_deferred_yieldable(curr_writer)

        @contextmanager
        def _ctx_manager():
            try:
                yield
            finally:
                new_defer.callback(None)
                self.key_to_current_readers.get(key, set()).discard(new_defer)

        return _ctx_manager()

    async def write(self, key: str) -> ContextManager:
        new_defer = defer.Deferred()

        curr_readers = self.key_to_current_readers.get(key, set())
        curr_writer = self.key_to_current_writer.get(key, None)

        # We wait on all latest readers and writer.
        to_wait_on = list(curr_readers)
        if curr_writer:
            to_wait_on.append(curr_writer)

        # We can clear the list of current readers since the new writer waits
        # for them to finish.
        curr_readers.clear()
        self.key_to_current_writer[key] = new_defer

        await make_deferred_yieldable(defer.gatherResults(to_wait_on))

        @contextmanager
        def _ctx_manager():
            try:
                yield
            finally:
                new_defer.callback(None)
                if self.key_to_current_writer[key] == new_defer:
                    self.key_to_current_writer.pop(key)

        return _ctx_manager()


R = TypeVar("R")


def timeout_deferred(
    deferred: defer.Deferred,
    timeout: float,
    reactor: IReactorTime,
) -> defer.Deferred:
    """The in built twisted `Deferred.addTimeout` fails to time out deferreds
    that have a canceller that throws exceptions. This method creates a new
    deferred that wraps and times out the given deferred, correctly handling
    the case where the given deferred's canceller throws.

    (See https://twistedmatrix.com/trac/ticket/9534)

    NOTE: Unlike `Deferred.addTimeout`, this function returns a new deferred.

    NOTE: the TimeoutError raised by the resultant deferred is
    twisted.internet.defer.TimeoutError, which is *different* to the built-in
    TimeoutError, as well as various other TimeoutErrors you might have imported.

    Args:
        deferred: The Deferred to potentially timeout.
        timeout: Timeout in seconds
        reactor: The twisted reactor to use


    Returns:
        A new Deferred, which will errback with defer.TimeoutError on timeout.
    """
    new_d = defer.Deferred()

    timed_out = [False]

    def time_it_out():
        timed_out[0] = True

        try:
            deferred.cancel()
        except Exception:  # if we throw any exception it'll break time outs
            logger.exception("Canceller failed during timeout")

        # the cancel() call should have set off a chain of errbacks which
        # will have errbacked new_d, but in case it hasn't, errback it now.

        if not new_d.called:
            new_d.errback(defer.TimeoutError("Timed out after %gs" % (timeout,)))

    delayed_call = reactor.callLater(timeout, time_it_out)

    def convert_cancelled(value: failure.Failure):
        # if the original deferred was cancelled, and our timeout has fired, then
        # the reason it was cancelled was due to our timeout. Turn the CancelledError
        # into a TimeoutError.
        if timed_out[0] and value.check(CancelledError):
            raise defer.TimeoutError("Timed out after %gs" % (timeout,))
        return value

    deferred.addErrback(convert_cancelled)

    def cancel_timeout(result):
        # stop the pending call to cancel the deferred if it's been fired
        if delayed_call.active():
            delayed_call.cancel()
        return result

    deferred.addBoth(cancel_timeout)

    def success_cb(val):
        if not new_d.called:
            new_d.callback(val)

    def failure_cb(val):
        if not new_d.called:
            new_d.errback(val)

    deferred.addCallbacks(success_cb, failure_cb)

    return new_d


@attr.s(slots=True, frozen=True)
class DoneAwaitable:
    """Simple awaitable that returns the provided value."""

    value = attr.ib()

    def __await__(self):
        return self

    def __iter__(self):
        return self

    def __next__(self):
        raise StopIteration(self.value)


def maybe_awaitable(value: Union[Awaitable[R], R]) -> Awaitable[R]:
    """Convert a value to an awaitable if not already an awaitable."""
    if inspect.isawaitable(value):
        assert isinstance(value, Awaitable)
        return value

    return DoneAwaitable(value)
