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

"""
This code is based off `prometheus_client/exposition.py` from version 0.7.1.

Due to the renaming of metrics in prometheus_client 0.4.0, this customised
vendoring of the code will emit both the old versions that Synapse dashboards
expect, and the newer "best practice" version of the up-to-date official client.
"""

import math
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
from typing import Dict, List
from urllib.parse import parse_qs, urlparse

from prometheus_client import REGISTRY

from twisted.web.resource import Resource

from synapse.util import caches

CONTENT_TYPE_LATEST = str("text/plain; version=0.0.4; charset=utf-8")


INF = float("inf")
MINUS_INF = float("-inf")


def floatToGoString(d):
    d = float(d)
    if d == INF:
        return "+Inf"
    elif d == MINUS_INF:
        return "-Inf"
    elif math.isnan(d):
        return "NaN"
    else:
        s = repr(d)
        dot = s.find(".")
        # Go switches to exponents sooner than Python.
        # We only need to care about positive values for le/quantile.
        if d > 0 and dot > 6:
            mantissa = "{0}.{1}{2}".format(s[0], s[1:dot], s[dot + 1 :]).rstrip("0.")
            return "{0}e+0{1}".format(mantissa, dot - 1)
        return s


def sample_line(line, name):
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
        name, labelstr, floatToGoString(line.value), timestamp
    )


def generate_latest(registry, emit_help=False):

    # Trigger the cache metrics to be rescraped, which updates the common
    # metrics but do not produce metrics themselves
    for collector in caches.collectors_by_name.values():
        collector.collect()

    output = []

    for metric in registry.collect():
        if not metric.samples:
            # No samples, don't bother.
            continue

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
        if emit_help:
            output.append(
                "# HELP {0} {1}\n".format(
                    mname,
                    metric.documentation.replace("\\", r"\\").replace("\n", r"\n"),
                )
            )
        output.append("# TYPE {0} {1}\n".format(mname, mtype))

        om_samples = {}  # type: Dict[str, List[str]]
        for s in metric.samples:
            for suffix in ["_created", "_gsum", "_gcount"]:
                if s.name == metric.name + suffix:
                    # OpenMetrics specific sample, put in a gauge at the end.
                    # (these come from gaugehistograms which don't get renamed,
                    # so no need to faff with mnewname)
                    om_samples.setdefault(suffix, []).append(sample_line(s, s.name))
                    break
            else:
                newname = s.name.replace(mnewname, mname)
                if ":" in newname and newname.endswith("_total"):
                    newname = newname[: -len("_total")]
                output.append(sample_line(s, newname))

        for suffix, lines in sorted(om_samples.items()):
            if emit_help:
                output.append(
                    "# HELP {0}{1} {2}\n".format(
                        metric.name,
                        suffix,
                        metric.documentation.replace("\\", r"\\").replace("\n", r"\n"),
                    )
                )
            output.append("# TYPE {0}{1} gauge\n".format(metric.name, suffix))
            output.extend(lines)

        # Get rid of the weird colon things while we're at it
        if mtype == "counter":
            mnewname = mnewname.replace(":total", "")
        mnewname = mnewname.replace(":", "_")

        if mname == mnewname:
            continue

        # Also output in the new format, if it's different.
        if emit_help:
            output.append(
                "# HELP {0} {1}\n".format(
                    mnewname,
                    metric.documentation.replace("\\", r"\\").replace("\n", r"\n"),
                )
            )
        output.append("# TYPE {0} {1}\n".format(mnewname, mtype))

        for s in metric.samples:
            # Get rid of the OpenMetrics specific samples (we should already have
            # dealt with them above anyway.)
            for suffix in ["_created", "_gsum", "_gcount"]:
                if s.name == metric.name + suffix:
                    break
            else:
                output.append(
                    sample_line(s, s.name.replace(":total", "").replace(":", "_"))
                )

    return "".join(output).encode("utf-8")


class MetricsHandler(BaseHTTPRequestHandler):
    """HTTP handler that gives metrics from ``REGISTRY``."""

    registry = REGISTRY

    def do_GET(self):
        registry = self.registry
        params = parse_qs(urlparse(self.path).query)

        if "help" in params:
            emit_help = True
        else:
            emit_help = False

        try:
            output = generate_latest(registry, emit_help=emit_help)
        except Exception:
            self.send_error(500, "error generating metric output")
            raise
        self.send_response(200)
        self.send_header("Content-Type", CONTENT_TYPE_LATEST)
        self.send_header("Content-Length", str(len(output)))
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
        response = generate_latest(self.registry)
        request.setHeader(b"Content-Length", str(len(response)))
        return response
