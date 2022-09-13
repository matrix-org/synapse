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
from typing import TYPE_CHECKING, Any, Generator, Optional, Tuple, Union

import attr
from zope.interface import implementer

from twisted.internet.defer import Deferred
from twisted.internet.interfaces import IAddress, IReactorTime
from twisted.python.failure import Failure
from twisted.web.http import HTTPChannel
from twisted.web.resource import IResource, Resource
from twisted.web.server import Request, Site

from synapse.config.server import ListenerConfig
from synapse.http import get_request_user_agent, redact_uri
from synapse.http.request_metrics import RequestMetrics, requests_counter
from synapse.logging.context import (
    ContextRequest,
    LoggingContext,
    PreserveLoggingContext,
)
from synapse.types import Requester

if TYPE_CHECKING:
    import opentracing

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
     * A limit to the size of request which will be accepted

    It also provides a method `processing`, which returns a context manager. If this
    method is called, the request won't be logged until the context manager is closed;
    this is useful for asynchronous request handlers which may go on processing the
    request even after the client has disconnected.

    Attributes:
        logcontext: the log context for this request
    """

    def __init__(
        self,
        channel: HTTPChannel,
        site: "SynapseSite",
        *args: Any,
        max_request_body_size: int = 1024,
        request_id_header: Optional[str] = None,
        **kw: Any,
    ):
        super().__init__(channel, *args, **kw)
        self._max_request_body_size = max_request_body_size
        self.request_id_header = request_id_header
        self.synapse_site = site
        self.reactor = site.reactor
        self._channel = channel  # this is used by the tests
        self.start_time = 0.0

        # The requester, if authenticated. For federation requests this is the
        # server name, for client requests this is the Requester object.
        self._requester: Optional[Union[Requester, str]] = None

        # An opentracing span for this request. Will be closed when the request is
        # completely processed.
        self._opentracing_span: "Optional[opentracing.Span]" = None

        # we can't yet create the logcontext, as we don't know the method.
        self.logcontext: Optional[LoggingContext] = None

        # The `Deferred` to cancel if the client disconnects early and
        # `is_render_cancellable` is set. Expected to be set by `Resource.render`.
        self.render_deferred: Optional["Deferred[None]"] = None
        # A boolean indicating whether `render_deferred` should be cancelled if the
        # client disconnects early. Expected to be set by the coroutine started by
        # `Resource.render`, if rendering is asynchronous.
        self.is_render_cancellable = False

        global _next_request_seq
        self.request_seq = _next_request_seq
        _next_request_seq += 1

        # whether an asynchronous request handler has called processing()
        self._is_processing = False

        # the time when the asynchronous request handler completed its processing
        self._processing_finished_time: Optional[float] = None

        # what time we finished sending the response to the client (or the connection
        # dropped)
        self.finish_time: Optional[float] = None

    def __repr__(self) -> str:
        # We overwrite this so that we don't log ``access_token``
        return "<%s at 0x%x method=%r uri=%r clientproto=%r site=%r>" % (
            self.__class__.__name__,
            id(self),
            self.get_method(),
            self.get_redacted_uri(),
            self.clientproto.decode("ascii", errors="replace"),
            self.synapse_site.site_tag,
        )

    def handleContentChunk(self, data: bytes) -> None:
        # we should have a `content` by now.
        assert self.content, "handleContentChunk() called before gotLength()"
        if self.content.tell() + len(data) > self._max_request_body_size:
            logger.warning(
                "Aborting connection from %s because the request exceeds maximum size: %s %s",
                self.client,
                self.get_method(),
                self.get_redacted_uri(),
            )
            self.transport.abortConnection()
            return
        super().handleContentChunk(data)

    @property
    def requester(self) -> Optional[Union[Requester, str]]:
        return self._requester

    @requester.setter
    def requester(self, value: Union[Requester, str]) -> None:
        # Store the requester, and update some properties based on it.

        # This should only be called once.
        assert self._requester is None

        self._requester = value

        # A logging context should exist by now (and have a ContextRequest).
        assert self.logcontext is not None
        assert self.logcontext.request is not None

        (
            requester,
            authenticated_entity,
        ) = self.get_authenticated_entity()
        self.logcontext.request.requester = requester
        # If there's no authenticated entity, it was the requester.
        self.logcontext.request.authenticated_entity = authenticated_entity or requester

    def set_opentracing_span(self, span: "opentracing.Span") -> None:
        """attach an opentracing span to this request

        Doing so will cause the span to be closed when we finish processing the request
        """
        self._opentracing_span = span

    def get_request_id(self) -> str:
        request_id_value = None
        if self.request_id_header:
            request_id_value = self.getHeader(self.request_id_header)

        if request_id_value is None:
            request_id_value = str(self.request_seq)

        return "%s-%s" % (self.get_method(), request_id_value)

    def get_redacted_uri(self) -> str:
        """Gets the redacted URI associated with the request (or placeholder if the URI
        has not yet been received).

        Note: This is necessary as the placeholder value in twisted is str
        rather than bytes, so we need to sanitise `self.uri`.

        Returns:
            The redacted URI as a string.
        """
        uri: Union[bytes, str] = self.uri
        if isinstance(uri, bytes):
            uri = uri.decode("ascii", errors="replace")
        return redact_uri(uri)

    def get_method(self) -> str:
        """Gets the method associated with the request (or placeholder if method
        has not yet been received).

        Note: This is necessary as the placeholder value in twisted is str
        rather than bytes, so we need to sanitise `self.method`.

        Returns:
            The request method as a string.
        """
        method: Union[bytes, str] = self.method
        if isinstance(method, bytes):
            return self.method.decode("ascii")
        return method

    def get_authenticated_entity(self) -> Tuple[Optional[str], Optional[str]]:
        """
        Get the "authenticated" entity of the request, which might be the user
        performing the action, or a user being puppeted by a server admin.

        Returns:
            A tuple:
                The first item is a string representing the user making the request.

                The second item is a string or None representing the user who
                authenticated when making this request. See
                Requester.authenticated_entity.
        """
        # Convert the requester into a string that we can log
        if isinstance(self._requester, str):
            return self._requester, None
        elif isinstance(self._requester, Requester):
            requester = self._requester.user.to_string()
            authenticated_entity = self._requester.authenticated_entity

            # If this is a request where the target user doesn't match the user who
            # authenticated (e.g. and admin is puppetting a user) then we return both.
            if requester != authenticated_entity:
                return requester, authenticated_entity

            return requester, None
        elif self._requester is not None:
            # This shouldn't happen, but we log it so we don't lose information
            # and can see that we're doing something wrong.
            return repr(self._requester), None  # type: ignore[unreachable]

        return None, None

    def render(self, resrc: Resource) -> None:
        # this is called once a Resource has been found to serve the request; in our
        # case the Resource in question will normally be a JsonResource.

        # create a LogContext for this request
        request_id = self.get_request_id()
        self.logcontext = LoggingContext(
            request_id,
            request=ContextRequest(
                request_id=request_id,
                ip_address=self.getClientAddress().host,
                site_tag=self.synapse_site.site_tag,
                # The requester is going to be unknown at this point.
                requester=None,
                authenticated_entity=None,
                method=self.get_method(),
                url=self.get_redacted_uri(),
                protocol=self.clientproto.decode("ascii", errors="replace"),
                user_agent=get_request_user_agent(self),
            ),
        )

        # override the Server header which is set by twisted
        self.setHeader("Server", self.synapse_site.server_version_string)

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
            requests_counter.labels(self.get_method(), self.request_metrics.name).inc()

    @contextlib.contextmanager
    def processing(self) -> Generator[None, None, None]:
        """Record the fact that we are processing this request.

        Returns a context manager; the correct way to use this is:

        async def handle_request(request):
            with request.processing("FooServlet"):
                await really_handle_the_request()

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
            logger.exception(
                "Asynchronous message handler raised an uncaught exception"
            )
        finally:
            # the request handler has finished its work and either sent the whole response
            # back, or handed over responsibility to a Producer.

            self._processing_finished_time = time.time()
            self._is_processing = False

            if self._opentracing_span:
                self._opentracing_span.log_kv({"event": "finished processing"})

            # if we've already sent the response, log it now; otherwise, we wait for the
            # response to be sent.
            if self.finish_time is not None:
                self._finished_processing()

    def finish(self) -> None:
        """Called when all response data has been written to this Request.

        Overrides twisted.web.server.Request.finish to record the finish time and do
        logging.
        """
        self.finish_time = time.time()
        Request.finish(self)
        if self._opentracing_span:
            self._opentracing_span.log_kv({"event": "response sent"})
        if not self._is_processing:
            assert self.logcontext is not None
            with PreserveLoggingContext(self.logcontext):
                self._finished_processing()

    def connectionLost(self, reason: Union[Failure, Exception]) -> None:
        """Called when the client connection is closed before the response is written.

        Overrides twisted.web.server.Request.connectionLost to record the finish time and
        do logging.
        """
        # There is a bug in Twisted where reason is not wrapped in a Failure object
        # Detect this and wrap it manually as a workaround
        # More information: https://github.com/matrix-org/synapse/issues/7441
        if not isinstance(reason, Failure):
            reason = Failure(reason)

        self.finish_time = time.time()
        Request.connectionLost(self, reason)

        if self.logcontext is None:
            logger.info(
                "Connection from %s lost before request headers were read", self.client
            )
            return

        # we only get here if the connection to the client drops before we send
        # the response.
        #
        # It's useful to log it here so that we can get an idea of when
        # the client disconnects.
        with PreserveLoggingContext(self.logcontext):
            logger.info("Connection from client lost before response was sent")

            if self._opentracing_span:
                self._opentracing_span.log_kv(
                    {"event": "client connection lost", "reason": str(reason.value)}
                )

            if self._is_processing:
                if self.is_render_cancellable:
                    if self.render_deferred is not None:
                        # Throw a cancellation into the request processing, in the hope
                        # that it will finish up sooner than it normally would.
                        # The `self.processing()` context manager will call
                        # `_finished_processing()` when done.
                        with PreserveLoggingContext():
                            self.render_deferred.cancel()
                    else:
                        logger.error(
                            "Connection from client lost, but have no Deferred to "
                            "cancel even though the request is marked as cancellable."
                        )
            else:
                self._finished_processing()

    def _started_processing(self, servlet_name: str) -> None:
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
            self.start_time, name=servlet_name, method=self.get_method()
        )

        self.synapse_site.access_logger.debug(
            "%s - %s - Received request: %s %s",
            self.getClientAddress().host,
            self.synapse_site.site_tag,
            self.get_method(),
            self.get_redacted_uri(),
        )

    def _finished_processing(self) -> None:
        """Log the completion of this request and update the metrics"""
        assert self.logcontext is not None
        assert self.finish_time is not None

        usage = self.logcontext.get_resource_usage()

        if self._processing_finished_time is None:
            # we completed the request without anything calling processing()
            self._processing_finished_time = time.time()

        # the time between receiving the request and the request handler finishing
        processing_time = self._processing_finished_time - self.start_time

        # the time between the request handler finishing and the response being sent
        # to the client (nb may be negative)
        response_send_time = self.finish_time - self._processing_finished_time

        user_agent = get_request_user_agent(self, "-")

        # int(self.code) looks redundant, because self.code is already an int.
        # But self.code might be an HTTPStatus (which inherits from int)---which has
        # a different string representation. So ensure we really have an integer.
        code = str(int(self.code))
        if not self.finished:
            # we didn't send the full response before we gave up (presumably because
            # the connection dropped)
            code += "!"

        log_level = logging.INFO if self._should_log_request() else logging.DEBUG

        # If this is a request where the target user doesn't match the user who
        # authenticated (e.g. and admin is puppetting a user) then we log both.
        requester, authenticated_entity = self.get_authenticated_entity()
        if authenticated_entity:
            requester = f"{authenticated_entity}|{requester}"

        self.synapse_site.access_logger.log(
            log_level,
            "%s - %s - {%s}"
            " Processed request: %.3fsec/%.3fsec (%.3fsec, %.3fsec) (%.3fsec/%.3fsec/%d)"
            ' %sB %s "%s %s %s" "%s" [%d dbevts]',
            self.getClientAddress().host,
            self.synapse_site.site_tag,
            requester,
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
            self.clientproto.decode("ascii", errors="replace"),
            user_agent,
            usage.evt_db_fetch_count,
        )

        # complete the opentracing span, if any.
        if self._opentracing_span:
            self._opentracing_span.finish()

        try:
            self.request_metrics.stop(self.finish_time, self.code, self.sentLength)
        except Exception as e:
            logger.warning("Failed to stop metrics: %r", e)

    def _should_log_request(self) -> bool:
        """Whether we should log at INFO that we processed the request."""
        if self.path == b"/health":
            return False

        if self.method == b"OPTIONS":
            return False

        return True


class XForwardedForRequest(SynapseRequest):
    """Request object which honours proxy headers

    Extends SynapseRequest to replace getClientIP, getClientAddress, and isSecure with
    information from request headers.
    """

    # the client IP and ssl flag, as extracted from the headers.
    _forwarded_for: "Optional[_XForwardedForAddress]" = None
    _forwarded_https: bool = False

    def requestReceived(self, command: bytes, path: bytes, version: bytes) -> None:
        # this method is called by the Channel once the full request has been
        # received, to dispatch the request to a resource.
        # We can use it to set the IP address and protocol according to the
        # headers.
        self._process_forwarded_headers()
        return super().requestReceived(command, path, version)

    def _process_forwarded_headers(self) -> None:
        headers = self.requestHeaders.getRawHeaders(b"x-forwarded-for")
        if not headers:
            return

        # for now, we just use the first x-forwarded-for header. Really, we ought
        # to start from the client IP address, and check whether it is trusted; if it
        # is, work backwards through the headers until we find an untrusted address.
        # see https://github.com/matrix-org/synapse/issues/9471
        self._forwarded_for = _XForwardedForAddress(
            headers[0].split(b",")[0].strip().decode("ascii")
        )

        # if we got an x-forwarded-for header, also look for an x-forwarded-proto header
        header = self.getHeader(b"x-forwarded-proto")
        if header is not None:
            self._forwarded_https = header.lower() == b"https"
        else:
            # this is done largely for backwards-compatibility so that people that
            # haven't set an x-forwarded-proto header don't get a redirect loop.
            logger.warning(
                "forwarded request lacks an x-forwarded-proto header: assuming https"
            )
            self._forwarded_https = True

    def isSecure(self) -> bool:
        if self._forwarded_https:
            return True
        return super().isSecure()

    def getClientIP(self) -> str:
        """
        Return the IP address of the client who submitted this request.

        This method is deprecated.  Use getClientAddress() instead.
        """
        if self._forwarded_for is not None:
            return self._forwarded_for.host
        return super().getClientIP()

    def getClientAddress(self) -> IAddress:
        """
        Return the address of the client who submitted this request.
        """
        if self._forwarded_for is not None:
            return self._forwarded_for
        return super().getClientAddress()


@implementer(IAddress)
@attr.s(frozen=True, slots=True, auto_attribs=True)
class _XForwardedForAddress:
    host: str


class SynapseSite(Site):
    """
    Synapse-specific twisted http Site

    This does two main things.

    First, it replaces the requestFactory in use so that we build SynapseRequests
    instead of regular t.w.server.Requests. All of the  constructor params are really
    just parameters for SynapseRequest.

    Second, it inhibits the log() method called by Request.finish, since SynapseRequest
    does its own logging.
    """

    def __init__(
        self,
        logger_name: str,
        site_tag: str,
        config: ListenerConfig,
        resource: IResource,
        server_version_string: str,
        max_request_body_size: int,
        reactor: IReactorTime,
    ):
        """

        Args:
            logger_name:  The name of the logger to use for access logs.
            site_tag:  A tag to use for this site - mostly in access logs.
            config:  Configuration for the HTTP listener corresponding to this site
            resource:  The base of the resource tree to be used for serving requests on
                this site
            server_version_string: A string to present for the Server header
            max_request_body_size: Maximum request body length to allow before
                dropping the connection
            reactor: reactor to be used to manage connection timeouts
        """
        Site.__init__(self, resource, reactor=reactor)

        self.site_tag = site_tag
        self.reactor = reactor

        assert config.http_options is not None
        proxied = config.http_options.x_forwarded
        request_class = XForwardedForRequest if proxied else SynapseRequest

        request_id_header = config.http_options.request_id_header

        def request_factory(channel: HTTPChannel, queued: bool) -> Request:
            return request_class(
                channel,
                self,
                max_request_body_size=max_request_body_size,
                queued=queued,
                request_id_header=request_id_header,
            )

        self.requestFactory = request_factory  # type: ignore
        self.access_logger = logging.getLogger(logger_name)
        self.server_version_string = server_version_string.encode("ascii")

    def log(self, request: SynapseRequest) -> None:
        pass
