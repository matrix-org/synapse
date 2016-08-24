# -*- coding: utf-8 -*-
# Copyright 2016 OpenMarket Ltd
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

from synapse.util.logcontext import LoggingContext
import synapse.metrics

from functools import wraps
import logging


logger = logging.getLogger(__name__)


metrics = synapse.metrics.get_metrics_for(__name__)

block_timer = metrics.register_distribution(
    "block_timer",
    labels=["block_name"]
)

block_ru_utime = metrics.register_distribution(
    "block_ru_utime", labels=["block_name"]
)

block_ru_stime = metrics.register_distribution(
    "block_ru_stime", labels=["block_name"]
)

block_db_txn_count = metrics.register_distribution(
    "block_db_txn_count", labels=["block_name"]
)

block_db_txn_duration = metrics.register_distribution(
    "block_db_txn_duration", labels=["block_name"]
)


def measure_func(name):
    def wrapper(func):
        @wraps(func)
        @defer.inlineCallbacks
        def measured_func(self, *args, **kwargs):
            with Measure(self.clock, name):
                r = yield func(self, *args, **kwargs)
            defer.returnValue(r)
        return measured_func
    return wrapper


class Measure(object):
    __slots__ = [
        "clock", "name", "start_context", "start", "new_context", "ru_utime",
        "ru_stime", "db_txn_count", "db_txn_duration", "created_context"
    ]

    def __init__(self, clock, name):
        self.clock = clock
        self.name = name
        self.start_context = None
        self.start = None
        self.created_context = False

    def __enter__(self):
        self.start = self.clock.time_msec()
        self.start_context = LoggingContext.current_context()
        if not self.start_context:
            self.start_context = LoggingContext("Measure")
            self.start_context.__enter__()
            self.created_context = True

        self.ru_utime, self.ru_stime = self.start_context.get_resource_usage()
        self.db_txn_count = self.start_context.db_txn_count
        self.db_txn_duration = self.start_context.db_txn_duration

    def __exit__(self, exc_type, exc_val, exc_tb):
        if isinstance(exc_type, Exception) or not self.start_context:
            return

        duration = self.clock.time_msec() - self.start
        block_timer.inc_by(duration, self.name)

        context = LoggingContext.current_context()

        if context != self.start_context:
            logger.warn(
                "Context has unexpectedly changed from '%s' to '%s'. (%r)",
                self.start_context, context, self.name
            )
            return

        if not context:
            logger.warn("Expected context. (%r)", self.name)
            return

        ru_utime, ru_stime = context.get_resource_usage()

        block_ru_utime.inc_by(ru_utime - self.ru_utime, self.name)
        block_ru_stime.inc_by(ru_stime - self.ru_stime, self.name)
        block_db_txn_count.inc_by(
            context.db_txn_count - self.db_txn_count, self.name
        )
        block_db_txn_duration.inc_by(
            context.db_txn_duration - self.db_txn_duration, self.name
        )

        if self.created_context:
            self.start_context.__exit__(exc_type, exc_val, exc_tb)
