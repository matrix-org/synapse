# -*- coding: utf-8 -*-
# Copyright 2014 OpenMarket Ltd
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

from synapse.util.logcontext import LoggingContext

from twisted.internet import reactor

import time


class Clock(object):
    """A small utility that obtains current time-of-day so that time may be
    mocked during unit-tests.

    TODO(paul): Also move the sleep() functionallity into it
    """

    def time(self):
        """Returns the current system time in seconds since epoch."""
        return time.time()

    def time_msec(self):
        """Returns the current system time in miliseconds since epoch."""
        return self.time() * 1000

    def call_later(self, delay, callback):
        current_context = LoggingContext.current_context()
        def wrapped_callback():
            LoggingContext.thread_local.current_context = current_context
            callback()
        return reactor.callLater(delay, wrapped_callback)

    def cancel_call_later(self, timer):
        timer.cancel()
