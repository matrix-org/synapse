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
from itertools import islice

import attr

from twisted.internet import defer, task

from synapse.util.logcontext import PreserveLoggingContext

logger = logging.getLogger(__name__)


def unwrapFirstError(failure):
    # defer.gatherResults and DeferredLists wrap failures.
    failure.trap(defer.FirstError)
    return failure.value.subFailure


@attr.s
class Clock(object):
    """
    A Clock wraps a Twisted reactor and provides utilities on top of it.

    Args:
        reactor: The Twisted reactor to use.
    """
    _reactor = attr.ib()

    @defer.inlineCallbacks
    def sleep(self, seconds):
        d = defer.Deferred()
        with PreserveLoggingContext():
            self._reactor.callLater(seconds, d.callback, seconds)
            res = yield d
        defer.returnValue(res)

    def time(self):
        """Returns the current system time in seconds since epoch."""
        return self._reactor.seconds()

    def time_msec(self):
        """Returns the current system time in miliseconds since epoch."""
        return int(self.time() * 1000)

    def looping_call(self, f, msec):
        """Call a function repeatedly.

         Waits `msec` initially before calling `f` for the first time.

        Args:
            f(function): The function to call repeatedly.
            msec(float): How long to wait between calls in milliseconds.
        """
        call = task.LoopingCall(f)
        call.clock = self._reactor
        d = call.start(msec / 1000.0, now=False)
        d.addErrback(
            log_failure, "Looping call died", consumeErrors=False,
        )
        return call

    def call_later(self, delay, callback, *args, **kwargs):
        """Call something later

        Args:
            delay(float): How long to wait in seconds.
            callback(function): Function to call
            *args: Postional arguments to pass to function.
            **kwargs: Key arguments to pass to function.
        """
        def wrapped_callback(*args, **kwargs):
            with PreserveLoggingContext():
                callback(*args, **kwargs)

        with PreserveLoggingContext():
            return self._reactor.callLater(delay, wrapped_callback, *args, **kwargs)

    def cancel_call_later(self, timer, ignore_errs=False):
        try:
            timer.cancel()
        except Exception:
            if not ignore_errs:
                raise


def batch_iter(iterable, size):
    """batch an iterable up into tuples with a maximum size

    Args:
        iterable (iterable): the iterable to slice
        size (int): the maximum batch size

    Returns:
        an iterator over the chunks
    """
    # make sure we can deal with iterables like lists too
    sourceiter = iter(iterable)
    # call islice until it returns an empty tuple
    return iter(lambda: tuple(islice(sourceiter, size)), ())


def log_failure(failure, msg, consumeErrors=True):
    """Creates a function suitable for passing to `Deferred.addErrback` that
    logs any failures that occur.

    Args:
        msg (str): Message to log
        consumeErrors (bool): If true consumes the failure, otherwise passes
            on down the callback chain

    Returns:
        func(Failure)
    """

    logger.error(
        msg,
        exc_info=(
            failure.type,
            failure.value,
            failure.getTracebackObject()
        )
    )

    if not consumeErrors:
        return failure
