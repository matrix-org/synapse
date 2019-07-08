# -*- coding: utf-8 -*-
# Copyright 2015-2019 Prometheus Python Client Developers
# Copyright 2019 Matrix.org Foundation C.I.C.
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

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
from urllib.parse import parse_qs, urlparse

from prometheus_client.registry import REGISTRY
from prometheus_client.utils import floatToGoString

from twisted.web.resource import Resource

CONTENT_TYPE_LATEST = str("text/plain; version=0.0.4; charset=utf-8")


def sample_line(line):
    if line.labels:
        labelstr = "{{{0}}}".format(
            ",".join(
                [
                    '{0}="{1}"'.format(
                        k,
                        v.replace("\\", r"\\").replace("\n", r"\n").replace('"', r"\""),
                    )
                    for k, v in sorted(line.labels.items())
                ]
            )
        )
    else:
        labelstr = ""
    timestamp = ""
    if line.timestamp is not None:
        # Convert to milliseconds.
        timestamp = " {0:d}".format(int(float(line.timestamp) * 1000))
    return "{0}{1} {2}{3}\n".format(
        line.name, labelstr, floatToGoString(line.value), timestamp
    )


def generate_latest(registry):
    output = []

    for metric in registry.collect():

        mname = metric.name
        mnewname = metric.name
        mtype = metric.type

        # OpenMetrics -> Prometheus
        if mtype == "counter":
            mnewname = mnewname + "_total"
        elif mtype == "info":
            mtype = "gauge"
            mnewname = mnewname + "_info"
        elif mtype == "stateset":
            mtype = "gauge"
        elif mtype == "gaugehistogram":
            mtype = "histogram"
        elif mtype == "unknown":
            mtype = "untyped"

        # Output in the old format for compatibility.
        output.append("# TYPE {0} {1}\n".format(mname, mtype))
        for sample in metric.samples:
            output.append(sample_line(sample))

        # Also output in the new format.
        output.append("# TYPE {0} {1}\n".format(mnewname, mtype))
        for sample in metric.samples:
            output.append(sample_line(sample))

    return "".join(output).encode("utf-8")


class MetricsHandler(BaseHTTPRequestHandler):
    """HTTP handler that gives metrics from ``REGISTRY``."""

    registry = REGISTRY

    def do_GET(self):
        registry = self.registry
        params = parse_qs(urlparse(self.path).query)
        if "name[]" in params:
            registry = registry.restricted_registry(params["name[]"])
        try:
            output = generate_latest(registry)
        except Exception:
            self.send_error(500, "error generating metric output")
            raise
        self.send_response(200)
        self.send_header("Content-Type", CONTENT_TYPE_LATEST)
        self.end_headers()
        self.wfile.write(output)

    def log_message(self, format, *args):
        """Log nothing."""

    @classmethod
    def factory(cls, registry):
        """Returns a dynamic MetricsHandler class tied
           to the passed registry.
        """
        # This implementation relies on MetricsHandler.registry
        #  (defined above and defaulted to REGISTRY).

        # As we have unicode_literals, we need to create a str()
        #  object for type().
        cls_name = str(cls.__name__)
        MyMetricsHandler = type(cls_name, (cls, object), {"registry": registry})
        return MyMetricsHandler


class _ThreadingSimpleServer(ThreadingMixIn, HTTPServer):
    """Thread per request HTTP server."""

    # Make worker threads "fire and forget". Beginning with Python 3.7 this
    # prevents a memory leak because ``ThreadingMixIn`` starts to gather all
    # non-daemon threads in a list in order to join on them at server close.
    # Enabling daemon threads virtually makes ``_ThreadingSimpleServer`` the
    # same as Python 3.7's ``ThreadingHTTPServer``.
    daemon_threads = True


def start_http_server(port, addr="", registry=REGISTRY):
    """Starts an HTTP server for prometheus metrics as a daemon thread"""
    CustomMetricsHandler = MetricsHandler.factory(registry)
    httpd = _ThreadingSimpleServer((addr, port), CustomMetricsHandler)
    t = threading.Thread(target=httpd.serve_forever)
    t.daemon = True
    t.start()


class MetricsResource(Resource):
    """
    Twisted ``Resource`` that serves prometheus metrics.
    """

    isLeaf = True

    def __init__(self, registry=REGISTRY):
        self.registry = registry

    def render_GET(self, request):
        request.setHeader(b"Content-Type", CONTENT_TYPE_LATEST.encode("ascii"))
        return generate_latest(self.registry)
