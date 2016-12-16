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

from synapse.api.errors import SynapseError
from synapse.util.logcontext import PreserveLoggingContext

from twisted.internet import defer, reactor, task

import time
import logging

logger = logging.getLogger(__name__)


class DeferredTimedOutError(SynapseError):
    def __init__(self):
        super(SynapseError).__init__(504, "Timed out")


def unwrapFirstError(failure):
    # defer.gatherResults and DeferredLists wrap failures.
    failure.trap(defer.FirstError)
    return failure.value.subFailure


class Clock(object):
    """A small utility that obtains current time-of-day so that time may be
    mocked during unit-tests.

    TODO(paul): Also move the sleep() functionality into it
    """

    def time(self):
        """Returns the current system time in seconds since epoch."""
        return time.time()

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
        l = task.LoopingCall(f)
        l.start(msec / 1000.0, now=False)
        return l

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
            return reactor.callLater(delay, wrapped_callback, *args, **kwargs)

    def cancel_call_later(self, timer, ignore_errs=False):
        try:
            timer.cancel()
        except:
            if not ignore_errs:
                raise

    def time_bound_deferred(self, given_deferred, time_out):
        if given_deferred.called:
            return given_deferred

        ret_deferred = defer.Deferred()

        def timed_out_fn():
            try:
                ret_deferred.errback(DeferredTimedOutError())
            except:
                pass

            try:
                given_deferred.cancel()
            except:
                pass

        timer = None

        def cancel(res):
            try:
                self.cancel_call_later(timer)
            except:
                pass
            return res

        ret_deferred.addBoth(cancel)

        def sucess(res):
            try:
                ret_deferred.callback(res)
            except:
                pass

            return res

        def err(res):
            try:
                ret_deferred.errback(res)
            except:
                pass

        given_deferred.addCallbacks(callback=sucess, errback=err)

        timer = self.call_later(time_out, timed_out_fn)

        return ret_deferred
