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

from prometheus_client.core import Counter, Histogram
from synapse.metrics import LaterGauge

from synapse.util.logcontext import LoggingContext

logger = logging.getLogger(__name__)


# total number of responses served, split by method/servlet/tag
response_count = Counter(
    "synapse_http_server_response_count", "", ["method", "servlet", "tag"]
)

requests_counter = Counter(
    "synapse_http_server_requests_received", "", ["method", "servlet"]
)

outgoing_responses_counter = Counter(
    "synapse_http_server_responses", "", ["method", "code"]
)

response_timer = Histogram(
    "synapse_http_server_response_time_seconds", "sec", ["method", "servlet", "tag"]
)

response_ru_utime = Counter(
    "synapse_http_server_response_ru_utime_seconds", "sec", ["method", "servlet", "tag"]
)

response_ru_stime = Counter(
    "synapse_http_server_response_ru_stime_seconds", "sec", ["method", "servlet", "tag"]
)

response_db_txn_count = Counter(
    "synapse_http_server_response_db_txn_count", "", ["method", "servlet", "tag"]
)

# seconds spent waiting for db txns, excluding scheduling time, when processing
# this request
response_db_txn_duration = Counter(
    "synapse_http_server_response_db_txn_duration_seconds",
    "",
    ["method", "servlet", "tag"],
)

# seconds spent waiting for a db connection, when processing this request
response_db_sched_duration = Counter(
    "synapse_http_server_response_db_sched_duration_seconds",
    "",
    ["method", "servlet", "tag"],
)

# size in bytes of the response written
response_size = Counter(
    "synapse_http_server_response_size", "", ["method", "servlet", "tag"]
)

# In flight metrics are incremented while the requests are in flight, rather
# than when the response was written.

in_flight_requests_ru_utime = Counter(
    "synapse_http_server_in_flight_requests_ru_utime_seconds",
    "",
    ["method", "servlet"],
)

in_flight_requests_ru_stime = Counter(
    "synapse_http_server_in_flight_requests_ru_stime_seconds",
    "",
    ["method", "servlet"],
)

in_flight_requests_db_txn_count = Counter(
    "synapse_http_server_in_flight_requests_db_txn_count", "", ["method", "servlet"]
)

# seconds spent waiting for db txns, excluding scheduling time, when processing
# this request
in_flight_requests_db_txn_duration = Counter(
    "synapse_http_server_in_flight_requests_db_txn_duration_seconds",
    "",
    ["method", "servlet"],
)

# seconds spent waiting for a db connection, when processing this request
in_flight_requests_db_sched_duration = Counter(
    "synapse_http_server_in_flight_requests_db_sched_duration_seconds",
    "",
    ["method", "servlet"],
)

# The set of all in flight requests, set[RequestMetrics]
_in_flight_requests = set()


def _get_in_flight_counts():
    """Returns a count of all in flight requests by (method, server_name)

    Returns:
        dict[tuple[str, str], int]
    """
    for rm in _in_flight_requests:
        rm.update_metrics()

    # Map from (method, name) -> int, the number of in flight requests of that
    # type
    counts = {}
    for rm in _in_flight_requests:
        key = (rm.method, rm.name,)
        counts[key] = counts.get(key, 0) + 1

    return counts


LaterGauge(
    "synapse_http_request_metrics_in_flight_requests_count",
    "",
    ["method", "servlet"],
    _get_in_flight_counts,
)


class RequestMetrics(object):
    def start(self, time_sec, name, method):
        self.start = time_sec
        self.start_context = LoggingContext.current_context()
        self.name = name
        self.method = method

        self._request_stats = _RequestStats.from_context(self.start_context)

        _in_flight_requests.add(self)

    def stop(self, time_sec, request):
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

        outgoing_responses_counter.labels(request.method, str(request.code)).inc()

        response_count.labels(request.method, self.name, tag).inc()

        response_timer.labels(request.method, self.name, tag).observe(
            time_sec - self.start
        )

        ru_utime, ru_stime = context.get_resource_usage()

        response_ru_utime.labels(request.method, self.name, tag).inc(ru_utime)
        response_ru_stime.labels(request.method, self.name, tag).inc(ru_stime)
        response_db_txn_count.labels(request.method, self.name, tag).inc(
            context.db_txn_count
        )
        response_db_txn_duration.labels(request.method, self.name, tag).inc(
            context.db_txn_duration_sec
        )
        response_db_sched_duration.labels(request.method, self.name, tag).inc(
            context.db_sched_duration_sec
        )

        response_size.labels(request.method, self.name, tag).inc(request.sentLength)

        # We always call this at the end to ensure that we update the metrics
        # regardless of whether a call to /metrics while the request was in
        # flight.
        self.update_metrics()

    def update_metrics(self):
        """Updates the in flight metrics with values from this request.
        """
        diff = self._request_stats.update(self.start_context)

        in_flight_requests_ru_utime.labels(self.method, self.name).inc(diff.ru_utime)
        in_flight_requests_ru_stime.labels(self.method, self.name).inc(diff.ru_stime)

        in_flight_requests_db_txn_count.labels(self.method, self.name).inc(
            diff.db_txn_count
        )

        in_flight_requests_db_txn_duration.labels(self.method, self.name).inc(
            diff.db_txn_duration_sec
        )

        in_flight_requests_db_sched_duration.labels(self.method, self.name).inc(
            diff.db_sched_duration_sec
        )


class _RequestStats(object):
    """Keeps tracks of various metrics for an in flight request.
    """

    __slots__ = [
        "ru_utime",
        "ru_stime",
        "db_txn_count",
        "db_txn_duration_sec",
        "db_sched_duration_sec",
    ]

    def __init__(
        self, ru_utime, ru_stime, db_txn_count, db_txn_duration_sec, db_sched_duration_sec
    ):
        self.ru_utime = ru_utime
        self.ru_stime = ru_stime
        self.db_txn_count = db_txn_count
        self.db_txn_duration_sec = db_txn_duration_sec
        self.db_sched_duration_sec = db_sched_duration_sec

    @staticmethod
    def from_context(context):
        ru_utime, ru_stime = context.get_resource_usage()

        return _RequestStats(
            ru_utime, ru_stime,
            context.db_txn_count,
            context.db_txn_duration_sec,
            context.db_sched_duration_sec,
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
            new.db_txn_duration_sec - self.db_txn_duration_sec,
            new.db_sched_duration_sec - self.db_sched_duration_sec,
        )

        self.ru_utime = new.ru_utime
        self.ru_stime = new.ru_stime
        self.db_txn_count = new.db_txn_count
        self.db_txn_duration_sec = new.db_txn_duration_sec
        self.db_sched_duration_sec = new.db_sched_duration_sec

        return diff
