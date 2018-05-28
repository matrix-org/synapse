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

import contextlib
import logging
import re
import time

from twisted.web.server import Site, Request

from synapse.http.request_metrics import RequestMetrics
from synapse.util.logcontext import LoggingContext

logger = logging.getLogger(__name__)

ACCESS_TOKEN_RE = re.compile(br'(\?.*access(_|%5[Ff])token=)[^&]*(.*)$')

_next_request_seq = 0


class SynapseRequest(Request):
    """Class which encapsulates an HTTP request to synapse.

    All of the requests processed in synapse are of this type.

    It extends twisted's twisted.web.server.Request, and adds:
     * Unique request ID
     * Redaction of access_token query-params in __repr__
     * Logging at start and end
     * Metrics to record CPU, wallclock and DB time by endpoint.

    It provides a method `processing` which should be called by the Resource
    which is handling the request, and returns a context manager.

    """
    def __init__(self, site, *args, **kw):
        Request.__init__(self, *args, **kw)
        self.site = site
        self.authenticated_entity = None
        self.start_time = 0

        global _next_request_seq
        self.request_seq = _next_request_seq
        _next_request_seq += 1

    def __repr__(self):
        # We overwrite this so that we don't log ``access_token``
        return '<%s at 0x%x method=%s uri=%s clientproto=%s site=%s>' % (
            self.__class__.__name__,
            id(self),
            self.method,
            self.get_redacted_uri(),
            self.clientproto,
            self.site.site_tag,
        )

    def get_request_id(self):
        return "%s-%i" % (self.method, self.request_seq)

    def get_redacted_uri(self):
        return ACCESS_TOKEN_RE.sub(
            br'\1<redacted>\3',
            self.uri
        )

    def get_user_agent(self):
        return self.requestHeaders.getRawHeaders(b"User-Agent", [None])[-1]

    def render(self, resrc):
        # override the Server header which is set by twisted
        self.setHeader("Server", self.site.server_version_string)
        return Request.render(self, resrc)

    def _started_processing(self, servlet_name):
        self.start_time = int(time.time() * 1000)
        self.request_metrics = RequestMetrics()
        self.request_metrics.start(
            self.start_time, name=servlet_name, method=self.method,
        )

        self.site.access_logger.info(
            "%s - %s - Received request: %s %s",
            self.getClientIP(),
            self.site.site_tag,
            self.method,
            self.get_redacted_uri()
        )

    def _finished_processing(self):
        try:
            context = LoggingContext.current_context()
            ru_utime, ru_stime = context.get_resource_usage()
            db_txn_count = context.db_txn_count
            db_txn_duration_ms = context.db_txn_duration_ms
            db_sched_duration_ms = context.db_sched_duration_ms
        except Exception:
            ru_utime, ru_stime = (0, 0)
            db_txn_count, db_txn_duration_ms = (0, 0)

        end_time = int(time.time() * 1000)

        self.site.access_logger.info(
            "%s - %s - {%s}"
            " Processed request: %dms (%dms, %dms) (%dms/%dms/%d)"
            " %sB %s \"%s %s %s\" \"%s\"",
            self.getClientIP(),
            self.site.site_tag,
            self.authenticated_entity,
            end_time - self.start_time,
            int(ru_utime * 1000),
            int(ru_stime * 1000),
            db_sched_duration_ms,
            db_txn_duration_ms,
            int(db_txn_count),
            self.sentLength,
            self.code,
            self.method,
            self.get_redacted_uri(),
            self.clientproto,
            self.get_user_agent(),
        )

        try:
            self.request_metrics.stop(end_time, self)
        except Exception as e:
            logger.warn("Failed to stop metrics: %r", e)

    @contextlib.contextmanager
    def processing(self, servlet_name):
        """Record the fact that we are processing this request.

        Returns a context manager; the correct way to use this is:

        @defer.inlineCallbacks
        def handle_request(request):
            with request.processing("FooServlet"):
                yield really_handle_the_request()

        This will log the request's arrival. Once the context manager is
        closed, the completion of the request will be logged, and the various
        metrics will be updated.

        Args:
            servlet_name (str): the name of the servlet which will be
                processing this request. This is used in the metrics.

                It is possible to update this afterwards by updating
                self.request_metrics.servlet_name.
        """
        # TODO: we should probably just move this into render() and finish(),
        # to save having to call a separate method.
        self._started_processing(servlet_name)
        yield
        self._finished_processing()


class XForwardedForRequest(SynapseRequest):
    def __init__(self, *args, **kw):
        SynapseRequest.__init__(self, *args, **kw)

    """
    Add a layer on top of another request that only uses the value of an
    X-Forwarded-For header as the result of C{getClientIP}.
    """
    def getClientIP(self):
        """
        @return: The client address (the first address) in the value of the
            I{X-Forwarded-For header}.  If the header is not present, return
            C{b"-"}.
        """
        return self.requestHeaders.getRawHeaders(
            b"x-forwarded-for", [b"-"])[0].split(b",")[0].strip()


class SynapseRequestFactory(object):
    def __init__(self, site, x_forwarded_for):
        self.site = site
        self.x_forwarded_for = x_forwarded_for

    def __call__(self, *args, **kwargs):
        if self.x_forwarded_for:
            return XForwardedForRequest(self.site, *args, **kwargs)
        else:
            return SynapseRequest(self.site, *args, **kwargs)


class SynapseSite(Site):
    """
    Subclass of a twisted http Site that does access logging with python's
    standard logging
    """
    def __init__(self, logger_name, site_tag, config, resource,
                 server_version_string, *args, **kwargs):
        Site.__init__(self, resource, *args, **kwargs)

        self.site_tag = site_tag

        proxied = config.get("x_forwarded", False)
        self.requestFactory = SynapseRequestFactory(self, proxied)
        self.access_logger = logging.getLogger(logger_name)
        self.server_version_string = server_version_string

    def log(self, request):
        pass
