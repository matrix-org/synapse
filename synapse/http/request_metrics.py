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

import logging

import synapse.metrics
from synapse.util.logcontext import LoggingContext

logger = logging.getLogger(__name__)

metrics = synapse.metrics.get_metrics_for("synapse.http.server")

# total number of responses served, split by method/servlet/tag
response_count = metrics.register_counter(
    "response_count",
    labels=["method", "servlet", "tag"],
    alternative_names=(
        # the following are all deprecated aliases for the same metric
        metrics.name_prefix + x for x in (
            "_requests",
            "_response_time:count",
            "_response_ru_utime:count",
            "_response_ru_stime:count",
            "_response_db_txn_count:count",
            "_response_db_txn_duration:count",
        )
    )
)

requests_counter = metrics.register_counter(
    "requests_received",
    labels=["method", "servlet", ],
)

outgoing_responses_counter = metrics.register_counter(
    "responses",
    labels=["method", "code"],
)

response_timer = metrics.register_counter(
    "response_time_seconds",
    labels=["method", "servlet", "tag"],
    alternative_names=(
        metrics.name_prefix + "_response_time:total",
    ),
)

response_ru_utime = metrics.register_counter(
    "response_ru_utime_seconds", labels=["method", "servlet", "tag"],
    alternative_names=(
        metrics.name_prefix + "_response_ru_utime:total",
    ),
)

response_ru_stime = metrics.register_counter(
    "response_ru_stime_seconds", labels=["method", "servlet", "tag"],
    alternative_names=(
        metrics.name_prefix + "_response_ru_stime:total",
    ),
)

response_db_txn_count = metrics.register_counter(
    "response_db_txn_count", labels=["method", "servlet", "tag"],
    alternative_names=(
        metrics.name_prefix + "_response_db_txn_count:total",
    ),
)

# seconds spent waiting for db txns, excluding scheduling time, when processing
# this request
response_db_txn_duration = metrics.register_counter(
    "response_db_txn_duration_seconds", labels=["method", "servlet", "tag"],
    alternative_names=(
        metrics.name_prefix + "_response_db_txn_duration:total",
    ),
)

# seconds spent waiting for a db connection, when processing this request
response_db_sched_duration = metrics.register_counter(
    "response_db_sched_duration_seconds", labels=["method", "servlet", "tag"]
)

# size in bytes of the response written
response_size = metrics.register_counter(
    "response_size", labels=["method", "servlet", "tag"]
)


class RequestMetrics(object):
    def start(self, time_msec, name):
        self.start = time_msec
        self.start_context = LoggingContext.current_context()
        self.name = name

    def stop(self, time_msec, request):
        context = LoggingContext.current_context()

        tag = ""
        if context:
            tag = context.tag

            if context != self.start_context:
                logger.warn(
                    "Context have unexpectedly changed %r, %r",
                    context, self.start_context
                )
                return

        outgoing_responses_counter.inc(request.method, str(request.code))

        response_count.inc(request.method, self.name, tag)

        response_timer.inc_by(
            time_msec - self.start, request.method,
            self.name, tag
        )

        ru_utime, ru_stime = context.get_resource_usage()

        response_ru_utime.inc_by(
            ru_utime, request.method, self.name, tag
        )
        response_ru_stime.inc_by(
            ru_stime, request.method, self.name, tag
        )
        response_db_txn_count.inc_by(
            context.db_txn_count, request.method, self.name, tag
        )
        response_db_txn_duration.inc_by(
            context.db_txn_duration_ms / 1000., request.method, self.name, tag
        )
        response_db_sched_duration.inc_by(
            context.db_sched_duration_ms / 1000., request.method, self.name, tag
        )

        response_size.inc_by(request.sentLength, request.method, self.name, tag)
