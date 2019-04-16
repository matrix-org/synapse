# -*- coding: utf-8 -*-
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
import logging
from contextlib import contextmanager

from six.moves import range

from twisted.internet import defer
from twisted.internet.defer import CancelledError
from twisted.python import failure

from synapse.util import Clock, logcontext, unwrapFirstError

from .logcontext import (
    PreserveLoggingContext,
    make_deferred_yieldable,
    run_in_background,
)

logger = logging.getLogger(__name__)


class ObservableDeferred(object):
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

    def __init__(self, deferred, consumeErrors=False):
        object.__setattr__(self, "_deferred", deferred)
        object.__setattr__(self, "_result", None)
        object.__setattr__(self, "_observers", set())

        def callback(r):
            object.__setattr__(self, "_result", (True, r))
            while self._observers:
                try:
                    # TODO: Handle errors here.
                    self._observers.pop().callback(r)
                except Exception:
                    pass
            return r

        def errback(f):
            object.__setattr__(self, "_result", (False, f))
            while self._observers:
                try:
                    # TODO: Handle errors here.
                    self._observers.pop().errback(f)
                except Exception:
                    pass

            if consumeErrors:
                return None
            else:
                return f

        deferred.addCallbacks(callback, errback)

    def observe(self):
        """Observe the underlying deferred.

        Can return either a deferred if the underlying deferred is still pending
        (or has failed), or the actual value. Callers may need to use maybeDeferred.
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
            return res if success else defer.fail(res)

    def observers(self):
        return self._observers

    def has_called(self):
        return self._result is not None

    def has_succeeded(self):
        return self._result is not None and self._result[0] is True

    def get_result(self):
        return self._result[1]

    def __getattr__(self, name):
        return getattr(self._deferred, name)

    def __setattr__(self, name, value):
        setattr(self._deferred, name, value)

    def __repr__(self):
        return "<ObservableDeferred object at %s, result=%r, _deferred=%r>" % (
            id(self), self._result, self._deferred,
        )


def concurrently_execute(func, args, limit):
    """Executes the function with each argument conncurrently while limiting
    the number of concurrent executions.

    Args:
        func (func): Function to execute, should return a deferred.
        args (list): List of arguments to pass to func, each invocation of func
            gets a signle argument.
        limit (int): Maximum number of conccurent executions.

    Returns:
        deferred: Resolved when all function invocations have finished.
    """
    it = iter(args)

    @defer.inlineCallbacks
    def _concurrently_execute_inner():
        try:
            while True:
                yield func(next(it))
        except StopIteration:
            pass

    return logcontext.make_deferred_yieldable(defer.gatherResults([
        run_in_background(_concurrently_execute_inner)
        for _ in range(limit)
    ], consumeErrors=True)).addErrback(unwrapFirstError)


class Linearizer(object):
    """Limits concurrent access to resources based on a key. Useful to ensure
    only a few things happen at a time on a given resource.

    Example:

        with (yield limiter.queue("test_key")):
            # do some work.

    """
    def __init__(self, name=None, max_count=1, clock=None):
        """
        Args:
            max_count(int): The maximum number of concurrent accesses
        """
        if name is None:
            self.name = id(self)
        else:
            self.name = name

        if not clock:
            from twisted.internet import reactor
            clock = Clock(reactor)
        self._clock = clock
        self.max_count = max_count

        # key_to_defer is a map from the key to a 2 element list where
        # the first element is the number of things executing, and
        # the second element is an OrderedDict, where the keys are deferreds for the
        # things blocked from executing.
        self.key_to_defer = {}

    def queue(self, key):
        # we avoid doing defer.inlineCallbacks here, so that cancellation works correctly.
        # (https://twistedmatrix.com/trac/ticket/4632 meant that cancellations were not
        # propagated inside inlineCallbacks until Twisted 18.7)
        entry = self.key_to_defer.setdefault(key, [0, collections.OrderedDict()])

        # If the number of things executing is greater than the maximum
        # then add a deferred to the list of blocked items
        # When one of the things currently executing finishes it will callback
        # this item so that it can continue executing.
        if entry[0] >= self.max_count:
            res = self._await_lock(key)
        else:
            logger.debug(
                "Acquired uncontended linearizer lock %r for key %r", self.name, key,
            )
            entry[0] += 1
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
                entry[0] -= 1

                if entry[1]:
                    (next_def, _) = entry[1].popitem(last=False)

                    # we need to run the next thing in the sentinel context.
                    with PreserveLoggingContext():
                        next_def.callback(None)
                elif entry[0] == 0:
                    # We were the last thing for this key: remove it from the
                    # map.
                    del self.key_to_defer[key]

        res.addCallback(_ctx_manager)
        return res

    def _await_lock(self, key):
        """Helper for queue: adds a deferred to the queue

        Assumes that we've already checked that we've reached the limit of the number
        of lock-holders we allow. Creates a new deferred which is added to the list, and
        adds some management around cancellations.

        Returns the deferred, which will callback once we have secured the lock.

        """
        entry = self.key_to_defer[key]

        logger.debug(
            "Waiting to acquire linearizer lock %r for key %r", self.name, key,
        )

        new_defer = make_deferred_yieldable(defer.Deferred())
        entry[1][new_defer] = 1

        def cb(_r):
            logger.debug("Acquired linearizer lock %r for key %r", self.name, key)
            entry[0] += 1

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
                    "Cancelling wait for linearizer lock %r for key %r",
                    self.name, key,
                )

            else:
                logger.warn(
                    "Unexpected exception waiting for linearizer lock %r for key %r",
                    self.name, key,
                )

            # we just have to take ourselves back out of the queue.
            del entry[1][new_defer]
            return e

        new_defer.addCallbacks(cb, eb)
        return new_defer


class ReadWriteLock(object):
    """A deferred style read write lock.

    Example:

        with (yield read_write_lock.read("test_key")):
            # do some work
    """

    # IMPLEMENTATION NOTES
    #
    # We track the most recent queued reader and writer deferreds (which get
    # resolved when they release the lock).
    #
    # Read: We know its safe to acquire a read lock when the latest writer has
    # been resolved. The new reader is appeneded to the list of latest readers.
    #
    # Write: We know its safe to acquire the write lock when both the latest
    # writers and readers have been resolved. The new writer replaces the latest
    # writer.

    def __init__(self):
        # Latest readers queued
        self.key_to_current_readers = {}

        # Latest writer queued
        self.key_to_current_writer = {}

    @defer.inlineCallbacks
    def read(self, key):
        new_defer = defer.Deferred()

        curr_readers = self.key_to_current_readers.setdefault(key, set())
        curr_writer = self.key_to_current_writer.get(key, None)

        curr_readers.add(new_defer)

        # We wait for the latest writer to finish writing. We can safely ignore
        # any existing readers... as they're readers.
        yield make_deferred_yieldable(curr_writer)

        @contextmanager
        def _ctx_manager():
            try:
                yield
            finally:
                new_defer.callback(None)
                self.key_to_current_readers.get(key, set()).discard(new_defer)

        defer.returnValue(_ctx_manager())

    @defer.inlineCallbacks
    def write(self, key):
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

        yield make_deferred_yieldable(defer.gatherResults(to_wait_on))

        @contextmanager
        def _ctx_manager():
            try:
                yield
            finally:
                new_defer.callback(None)
                if self.key_to_current_writer[key] == new_defer:
                    self.key_to_current_writer.pop(key)

        defer.returnValue(_ctx_manager())


def _cancelled_to_timed_out_error(value, timeout):
    if isinstance(value, failure.Failure):
        value.trap(CancelledError)
        raise defer.TimeoutError(timeout, "Deferred")
    return value


def timeout_deferred(deferred, timeout, reactor, on_timeout_cancel=None):
    """The in built twisted `Deferred.addTimeout` fails to time out deferreds
    that have a canceller that throws exceptions. This method creates a new
    deferred that wraps and times out the given deferred, correctly handling
    the case where the given deferred's canceller throws.

    (See https://twistedmatrix.com/trac/ticket/9534)

    NOTE: Unlike `Deferred.addTimeout`, this function returns a new deferred

    Args:
        deferred (Deferred)
        timeout (float): Timeout in seconds
        reactor (twisted.interfaces.IReactorTime): The twisted reactor to use
        on_timeout_cancel (callable): A callable which is called immediately
            after the deferred times out, and not if this deferred is
            otherwise cancelled before the timeout.

            It takes an arbitrary value, which is the value of the deferred at
            that exact point in time (probably a CancelledError Failure), and
            the timeout.

            The default callable (if none is provided) will translate a
            CancelledError Failure into a defer.TimeoutError.

    Returns:
        Deferred
    """

    new_d = defer.Deferred()

    timed_out = [False]

    def time_it_out():
        timed_out[0] = True

        try:
            deferred.cancel()
        except:   # noqa: E722, if we throw any exception it'll break time outs
            logger.exception("Canceller failed during timeout")

        if not new_d.called:
            new_d.errback(defer.TimeoutError(timeout, "Deferred"))

    delayed_call = reactor.callLater(timeout, time_it_out)

    def convert_cancelled(value):
        if timed_out[0]:
            to_call = on_timeout_cancel or _cancelled_to_timed_out_error
            return to_call(value, timeout)
        return value

    deferred.addBoth(convert_cancelled)

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
