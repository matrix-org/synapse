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

# In flight metrics are incremented while the requests are in flight, rather
# than when the response was written.

in_flight_requests_ru_utime = metrics.register_counter(
    "in_flight_requests_ru_utime_seconds", labels=["method", "servlet"],
)

in_flight_requests_ru_stime = metrics.register_counter(
    "in_flight_requests_ru_stime_seconds", labels=["method", "servlet"],
)

in_flight_requests_db_txn_count = metrics.register_counter(
    "in_flight_requests_db_txn_count", labels=["method", "servlet"],
)

# seconds spent waiting for db txns, excluding scheduling time, when processing
# this request
in_flight_requests_db_txn_duration = metrics.register_counter(
    "in_flight_requests_db_txn_duration_seconds", labels=["method", "servlet"],
)

# seconds spent waiting for a db connection, when processing this request
in_flight_requests_db_sched_duration = metrics.register_counter(
    "in_flight_requests_db_sched_duration_seconds", labels=["method", "servlet"]
)


# The set of all in flight requests, set[RequestMetrics]
_in_flight_requests = set()


def _collect_in_flight():
    """Called just before metrics are collected, so we use it to update all
    the in flight request metrics
    """

    for rm in _in_flight_requests:
        rm.update_metrics()


metrics.register_collector(_collect_in_flight)


def _get_in_flight_counts():
    """Returns a count of all in flight requests by (method, server_name)

    Returns:
        dict[tuple[str, str], int]
    """

    # Map from (method, name) -> int, the number of in flight requests of that
    # type
    counts = {}
    for rm in _in_flight_requests:
        key = (rm.method, rm.name,)
        counts[key] = counts.get(key, 0) + 1

    return counts


metrics.register_callback(
    "in_flight_requests_count",
    _get_in_flight_counts,
    labels=["method", "servlet"]
)


class RequestMetrics(object):
    def start(self, time_msec, name, method):
        self.start = time_msec
        self.start_context = LoggingContext.current_context()
        self.name = name
        self.method = method

        self._request_stats = _RequestStats.from_context(self.start_context)

        _in_flight_requests.add(self)

    def stop(self, time_msec, request):
        _in_flight_requests.discard(self)

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

        # We always call this at the end to ensure that we update the metrics
        # regardless of whether a call to /metrics while the request was in
        # flight.
        self.update_metrics()

    def update_metrics(self):
        """Updates the in flight metrics with values from this request.
        """

        diff = self._request_stats.update(self.start_context)

        in_flight_requests_ru_utime.inc_by(
            diff.ru_utime, self.method, self.name,
        )

        in_flight_requests_ru_stime.inc_by(
            diff.ru_stime, self.method, self.name,
        )

        in_flight_requests_db_txn_count.inc_by(
            diff.db_txn_count, self.method, self.name,
        )

        in_flight_requests_db_txn_duration.inc_by(
            diff.db_txn_duration_ms / 1000., self.method, self.name,
        )

        in_flight_requests_db_sched_duration.inc_by(
            diff.db_sched_duration_ms / 1000., self.method, self.name,
        )


class _RequestStats(object):
    """Keeps tracks of various metrics for an in flight request.
    """

    __slots__ = [
        "ru_utime", "ru_stime",
        "db_txn_count", "db_txn_duration_ms", "db_sched_duration_ms",
    ]

    def __init__(self, ru_utime, ru_stime, db_txn_count,
                 db_txn_duration_ms, db_sched_duration_ms):
        self.ru_utime = ru_utime
        self.ru_stime = ru_stime
        self.db_txn_count = db_txn_count
        self.db_txn_duration_ms = db_txn_duration_ms
        self.db_sched_duration_ms = db_sched_duration_ms

    @staticmethod
    def from_context(context):
        ru_utime, ru_stime = context.get_resource_usage()

        return _RequestStats(
            ru_utime, ru_stime,
            context.db_txn_count,
            context.db_txn_duration_ms,
            context.db_sched_duration_ms,
        )

    def update(self, context):
        """Updates the current values and returns the difference between the
        old and new values.

        Returns:
            _RequestStats: The difference between the old and new values
        """
        new = _RequestStats.from_context(context)

        diff = _RequestStats(
            new.ru_utime - self.ru_utime,
            new.ru_stime - self.ru_stime,
            new.db_txn_count - self.db_txn_count,
            new.db_txn_duration_ms - self.db_txn_duration_ms,
            new.db_sched_duration_ms - self.db_sched_duration_ms,
        )

        self.ru_utime = new.ru_utime
        self.ru_stime = new.ru_stime
        self.db_txn_count = new.db_txn_count
        self.db_txn_duration_ms = new.db_txn_duration_ms
        self.db_sched_duration_ms = new.db_sched_duration_ms

        return diff
