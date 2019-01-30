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
import time

from twisted.web.server import Request, Site

from synapse.http import redact_uri
from synapse.http.request_metrics import RequestMetrics, requests_counter
from synapse.util.logcontext import LoggingContext, PreserveLoggingContext

logger = logging.getLogger(__name__)

_next_request_seq = 0


class SynapseRequest(Request):
    """Class which encapsulates an HTTP request to synapse.

    All of the requests processed in synapse are of this type.

    It extends twisted's twisted.web.server.Request, and adds:
     * Unique request ID
     * A log context associated with the request
     * Redaction of access_token query-params in __repr__
     * Logging at start and end
     * Metrics to record CPU, wallclock and DB time by endpoint.

    It also provides a method `processing`, which returns a context manager. If this
    method is called, the request won't be logged until the context manager is closed;
    this is useful for asynchronous request handlers which may go on processing the
    request even after the client has disconnected.

    Attributes:
        logcontext(LoggingContext) : the log context for this request
    """
    def __init__(self, site, channel, *args, **kw):
        Request.__init__(self, channel, *args, **kw)
        self.site = site
        self._channel = channel     # this is used by the tests
        self.authenticated_entity = None
        self.start_time = 0

        # we can't yet create the logcontext, as we don't know the method.
        self.logcontext = None

        global _next_request_seq
        self.request_seq = _next_request_seq
        _next_request_seq += 1

        # whether an asynchronous request handler has called processing()
        self._is_processing = False

        # the time when the asynchronous request handler completed its processing
        self._processing_finished_time = None

        # what time we finished sending the response to the client (or the connection
        # dropped)
        self.finish_time = None

    def __repr__(self):
        # We overwrite this so that we don't log ``access_token``
        return '<%s at 0x%x method=%r uri=%r clientproto=%r site=%r>' % (
            self.__class__.__name__,
            id(self),
            self.get_method(),
            self.get_redacted_uri(),
            self.clientproto.decode('ascii', errors='replace'),
            self.site.site_tag,
        )

    def get_request_id(self):
        return "%s-%i" % (self.get_method(), self.request_seq)

    def get_redacted_uri(self):
        uri = self.uri
        if isinstance(uri, bytes):
            uri = self.uri.decode('ascii')
        return redact_uri(uri)

    def get_method(self):
        """Gets the method associated with the request (or placeholder if not
        method has yet been received).

        Note: This is necessary as the placeholder value in twisted is str
        rather than bytes, so we need to sanitise `self.method`.

        Returns:
            str
        """
        method = self.method
        if isinstance(method, bytes):
            method = self.method.decode('ascii')
        return method

    def get_user_agent(self):
        return self.requestHeaders.getRawHeaders(b"User-Agent", [None])[-1]

    def render(self, resrc):
        # this is called once a Resource has been found to serve the request; in our
        # case the Resource in question will normally be a JsonResource.

        # create a LogContext for this request
        request_id = self.get_request_id()
        logcontext = self.logcontext = LoggingContext(request_id)
        logcontext.request = request_id

        # override the Server header which is set by twisted
        self.setHeader("Server", self.site.server_version_string)

        with PreserveLoggingContext(self.logcontext):
            # we start the request metrics timer here with an initial stab
            # at the servlet name. For most requests that name will be
            # JsonResource (or a subclass), and JsonResource._async_render
            # will update it once it picks a servlet.
            servlet_name = resrc.__class__.__name__
            self._started_processing(servlet_name)

            Request.render(self, resrc)

            # record the arrival of the request *after*
            # dispatching to the handler, so that the handler
            # can update the servlet name in the request
            # metrics
            requests_counter.labels(self.get_method(),
                                    self.request_metrics.name).inc()

    @contextlib.contextmanager
    def processing(self):
        """Record the fact that we are processing this request.

        Returns a context manager; the correct way to use this is:

        @defer.inlineCallbacks
        def handle_request(request):
            with request.processing("FooServlet"):
                yield really_handle_the_request()

        Once the context manager is closed, the completion of the request will be logged,
        and the various metrics will be updated.
        """
        if self._is_processing:
            raise RuntimeError("Request is already processing")
        self._is_processing = True

        try:
            yield
        except Exception:
            # this should already have been caught, and sent back to the client as a 500.
            logger.exception("Asynchronous messge handler raised an uncaught exception")
        finally:
            # the request handler has finished its work and either sent the whole response
            # back, or handed over responsibility to a Producer.

            self._processing_finished_time = time.time()
            self._is_processing = False

            # if we've already sent the response, log it now; otherwise, we wait for the
            # response to be sent.
            if self.finish_time is not None:
                self._finished_processing()

    def finish(self):
        """Called when all response data has been written to this Request.

        Overrides twisted.web.server.Request.finish to record the finish time and do
        logging.
        """
        self.finish_time = time.time()
        Request.finish(self)
        if not self._is_processing:
            with PreserveLoggingContext(self.logcontext):
                self._finished_processing()

    def connectionLost(self, reason):
        """Called when the client connection is closed before the response is written.

        Overrides twisted.web.server.Request.connectionLost to record the finish time and
        do logging.
        """
        self.finish_time = time.time()
        Request.connectionLost(self, reason)

        # we only get here if the connection to the client drops before we send
        # the response.
        #
        # It's useful to log it here so that we can get an idea of when
        # the client disconnects.
        with PreserveLoggingContext(self.logcontext):
            logger.warn(
                "Error processing request %r: %s %s", self, reason.type, reason.value,
            )

            if not self._is_processing:
                self._finished_processing()

    def _started_processing(self, servlet_name):
        """Record the fact that we are processing this request.

        This will log the request's arrival. Once the request completes,
        be sure to call finished_processing.

        Args:
            servlet_name (str): the name of the servlet which will be
                processing this request. This is used in the metrics.

                It is possible to update this afterwards by updating
                self.request_metrics.name.
        """
        self.start_time = time.time()
        self.request_metrics = RequestMetrics()
        self.request_metrics.start(
            self.start_time, name=servlet_name, method=self.get_method(),
        )

        self.site.access_logger.info(
            "%s - %s - Received request: %s %s",
            self.getClientIP(),
            self.site.site_tag,
            self.get_method(),
            self.get_redacted_uri()
        )

    def _finished_processing(self):
        """Log the completion of this request and update the metrics
        """

        if self.logcontext is None:
            # this can happen if the connection closed before we read the
            # headers (so render was never called). In that case we'll already
            # have logged a warning, so just bail out.
            return

        usage = self.logcontext.get_resource_usage()

        if self._processing_finished_time is None:
            # we completed the request without anything calling processing()
            self._processing_finished_time = time.time()

        # the time between receiving the request and the request handler finishing
        processing_time = self._processing_finished_time - self.start_time

        # the time between the request handler finishing and the response being sent
        # to the client (nb may be negative)
        response_send_time = self.finish_time - self._processing_finished_time

        # need to decode as it could be raw utf-8 bytes
        # from a IDN servname in an auth header
        authenticated_entity = self.authenticated_entity
        if authenticated_entity is not None and isinstance(authenticated_entity, bytes):
            authenticated_entity = authenticated_entity.decode("utf-8", "replace")

        # ...or could be raw utf-8 bytes in the User-Agent header.
        # N.B. if you don't do this, the logger explodes cryptically
        # with maximum recursion trying to log errors about
        # the charset problem.
        # c.f. https://github.com/matrix-org/synapse/issues/3471
        user_agent = self.get_user_agent()
        if user_agent is not None:
            user_agent = user_agent.decode("utf-8", "replace")
        else:
            user_agent = "-"

        code = str(self.code)
        if not self.finished:
            # we didn't send the full response before we gave up (presumably because
            # the connection dropped)
            code += "!"

        self.site.access_logger.info(
            "%s - %s - {%s}"
            " Processed request: %.3fsec/%.3fsec (%.3fsec, %.3fsec) (%.3fsec/%.3fsec/%d)"
            " %sB %s \"%s %s %s\" \"%s\" [%d dbevts]",
            self.getClientIP(),
            self.site.site_tag,
            authenticated_entity,
            processing_time,
            response_send_time,
            usage.ru_utime,
            usage.ru_stime,
            usage.db_sched_duration_sec,
            usage.db_txn_duration_sec,
            int(usage.db_txn_count),
            self.sentLength,
            code,
            self.get_method(),
            self.get_redacted_uri(),
            self.clientproto.decode('ascii', errors='replace'),
            user_agent,
            usage.evt_db_fetch_count,
        )

        try:
            self.request_metrics.stop(self.finish_time, self.code, self.sentLength)
        except Exception as e:
            logger.warn("Failed to stop metrics: %r", e)


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
            b"x-forwarded-for", [b"-"])[0].split(b",")[0].strip().decode('ascii')


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
        self.server_version_string = server_version_string.encode('ascii')

    def log(self, request):
        pass
