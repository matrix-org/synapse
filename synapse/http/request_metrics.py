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

from synapse.util.logcontext import LoggingContext

logger = logging.getLogger(__name__)


# total number of responses served, split by method/servlet/tag
response_count = Counter("synapse_http_server_response_count", "", ["method", "servlet", "tag"])

requests_counter = Counter("synapse_http_server_requests_received", "", ["method", "servlet"])

outgoing_responses_counter = Counter("synapse_http_server_responses", "", ["method", "code"])

response_timer = Histogram("synapse_http_server_response_time_seconds", "", ["method", "servlet", "tag"])

response_ru_utime = Counter("synapse_http_server_response_ru_utime_seconds", "", ["method", "servlet", "tag"])

response_ru_stime = Counter("synapse_http_server_response_ru_stime_seconds", "", ["method", "servlet", "tag"])

response_db_txn_count = Counter("synapse_http_server_response_db_txn_count", "", ["method", "servlet", "tag"])

# seconds spent waiting for db txns, excluding scheduling time, when processing
# this request
response_db_txn_duration = Counter("synapse_http_server_response_db_txn_duration_seconds", "", ["method", "servlet", "tag"])

# seconds spent waiting for a db connection, when processing this request
response_db_sched_duration = Counter("synapse_http_request_response_db_sched_duration_seconds", "", ["method", "servlet", "tag"]
)

# size in bytes of the response written
response_size = Counter("synapse_http_request_response_size", "", ["method", "servlet", "tag"]
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

        outgoing_responses_counter.labels(request.method, str(request.code)).inc()

        response_count.labels(request.method, self.name, tag).inc()

        response_timer.labels(request.method, self.name, tag).observe(time_msec - self.start)

        ru_utime, ru_stime = context.get_resource_usage()

        response_ru_utime.labels(request.method, self.name, tag).inc(ru_utime)
        response_ru_stime.labels(request.method, self.name, tag).inc(ru_stime)
        response_db_txn_count.labels(request.method, self.name, tag).inc(context.db_txn_count)
        response_db_txn_duration.labels(request.method, self.name, tag).inc(context.db_txn_duration_ms / 1000.)
        response_db_sched_duration.labels(request.method, self.name, tag).inc(
            context.db_sched_duration_ms / 1000.)

        response_size.labels(request.method, self.name, tag).inc(request.sentLength)
