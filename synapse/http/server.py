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

import abc
import html
import logging
import types
import urllib
from http import HTTPStatus
from inspect import isawaitable
from typing import (
    TYPE_CHECKING,
    Any,
    Awaitable,
    Callable,
    Dict,
    Iterable,
    Iterator,
    List,
    NoReturn,
    Optional,
    Pattern,
    Tuple,
    TypeVar,
    Union,
)

import attr
import jinja2
from canonicaljson import encode_canonical_json
from typing_extensions import Protocol
from zope.interface import implementer

from twisted.internet import defer, interfaces
from twisted.internet.defer import CancelledError
from twisted.python import failure
from twisted.web import resource
from twisted.web.server import NOT_DONE_YET, Request
from twisted.web.static import File
from twisted.web.util import redirectTo

from synapse.api.errors import (
    CodeMessageException,
    Codes,
    RedirectException,
    SynapseError,
    UnrecognizedRequestError,
)
from synapse.http.site import SynapseRequest
from synapse.logging.context import defer_to_thread, preserve_fn, run_in_background
from synapse.logging.opentracing import active_span, start_active_span, trace_servlet
from synapse.util import json_encoder
from synapse.util.caches import intern_dict
from synapse.util.iterutils import chunk_seq

if TYPE_CHECKING:
    import opentracing

    from synapse.server import HomeServer

logger = logging.getLogger(__name__)

HTML_ERROR_TEMPLATE = """<!DOCTYPE html>
<html lang=en>
  <head>
    <meta charset="utf-8">
    <title>Error {code}</title>
  </head>
  <body>
     <p>{msg}</p>
  </body>
</html>
"""

# A fictional HTTP status code for requests where the client has disconnected and we
# successfully cancelled the request. Used only for logging purposes. Clients will never
# observe this code unless cancellations leak across requests or we raise a
# `CancelledError` ourselves.
# Analogous to nginx's 499 status code:
# https://github.com/nginx/nginx/blob/release-1.21.6/src/http/ngx_http_request.h#L128-L134
HTTP_STATUS_REQUEST_CANCELLED = 499


F = TypeVar("F", bound=Callable[..., Any])


_cancellable_method_names = frozenset(
    {
        # `RestServlet`, `BaseFederationServlet` and `BaseFederationServerServlet`
        # methods
        "on_GET",
        "on_PUT",
        "on_POST",
        "on_DELETE",
        # `_AsyncResource`, `DirectServeHtmlResource` and `DirectServeJsonResource`
        # methods
        "_async_render_GET",
        "_async_render_PUT",
        "_async_render_POST",
        "_async_render_DELETE",
        "_async_render_OPTIONS",
        # `ReplicationEndpoint` methods
        "_handle_request",
    }
)


def cancellable(method: F) -> F:
    """Marks a servlet method as cancellable.

    Methods with this decorator will be cancelled if the client disconnects before we
    finish processing the request.

    During cancellation, `Deferred.cancel()` will be invoked on the `Deferred` wrapping
    the method. The `cancel()` call will propagate down to the `Deferred` that is
    currently being waited on. That `Deferred` will raise a `CancelledError`, which will
    propagate up, as per normal exception handling.

    Before applying this decorator to a new endpoint, you MUST recursively check
    that all `await`s in the function are on `async` functions or `Deferred`s that
    handle cancellation cleanly, otherwise a variety of bugs may occur, ranging from
    premature logging context closure, to stuck requests, to database corruption.

    Usage:
        class SomeServlet(RestServlet):
            @cancellable
            async def on_GET(self, request: SynapseRequest) -> ...:
                ...
    """
    if method.__name__ not in _cancellable_method_names and not any(
        method.__name__.startswith(prefix) for prefix in _cancellable_method_names
    ):
        raise ValueError(
            "@cancellable decorator can only be applied to servlet methods."
        )

    method.cancellable = True  # type: ignore[attr-defined]
    return method


def is_method_cancellable(method: Callable[..., Any]) -> bool:
    """Checks whether a servlet method has the `@cancellable` flag."""
    return getattr(method, "cancellable", False)


def return_json_error(f: failure.Failure, request: SynapseRequest) -> None:
    """Sends a JSON error response to clients."""

    if f.check(SynapseError):
        # mypy doesn't understand that f.check asserts the type.
        exc: SynapseError = f.value  # type: ignore
        error_code = exc.code
        error_dict = exc.error_dict()

        logger.info("%s SynapseError: %s - %s", request, error_code, exc.msg)
    elif f.check(CancelledError):
        error_code = HTTP_STATUS_REQUEST_CANCELLED
        error_dict = {"error": "Request cancelled", "errcode": Codes.UNKNOWN}

        if not request._disconnected:
            logger.error(
                "Got cancellation before client disconnection from %r: %r",
                request.request_metrics.name,
                request,
                exc_info=(f.type, f.value, f.getTracebackObject()),  # type: ignore[arg-type]
            )
    else:
        error_code = 500
        error_dict = {"error": "Internal server error", "errcode": Codes.UNKNOWN}

        logger.error(
            "Failed handle request via %r: %r",
            request.request_metrics.name,
            request,
            exc_info=(f.type, f.value, f.getTracebackObject()),  # type: ignore[arg-type]
        )

    # Only respond with an error response if we haven't already started writing,
    # otherwise lets just kill the connection
    if request.startedWriting:
        if request.transport:
            try:
                request.transport.abortConnection()
            except Exception:
                # abortConnection throws if the connection is already closed
                pass
    else:
        respond_with_json(
            request,
            error_code,
            error_dict,
            send_cors=True,
        )


def return_html_error(
    f: failure.Failure,
    request: Request,
    error_template: Union[str, jinja2.Template],
) -> None:
    """Sends an HTML error page corresponding to the given failure.

    Handles RedirectException and other CodeMessageExceptions (such as SynapseError)

    Args:
        f: the error to report
        request: the failing request
        error_template: the HTML template. Can be either a string (with `{code}`,
            `{msg}` placeholders), or a jinja2 template
    """
    if f.check(CodeMessageException):
        # mypy doesn't understand that f.check asserts the type.
        cme: CodeMessageException = f.value  # type: ignore
        code = cme.code
        msg = cme.msg

        if isinstance(cme, RedirectException):
            logger.info("%s redirect to %s", request, cme.location)
            request.setHeader(b"location", cme.location)
            request.cookies.extend(cme.cookies)
        elif isinstance(cme, SynapseError):
            logger.info("%s SynapseError: %s - %s", request, code, msg)
        else:
            logger.error(
                "Failed handle request %r",
                request,
                exc_info=(f.type, f.value, f.getTracebackObject()),  # type: ignore[arg-type]
            )
    elif f.check(CancelledError):
        code = HTTP_STATUS_REQUEST_CANCELLED
        msg = "Request cancelled"

        if not request._disconnected:
            logger.error(
                "Got cancellation before client disconnection when handling request %r",
                request,
                exc_info=(f.type, f.value, f.getTracebackObject()),  # type: ignore[arg-type]
            )
    else:
        code = HTTPStatus.INTERNAL_SERVER_ERROR
        msg = "Internal server error"

        logger.error(
            "Failed handle request %r",
            request,
            exc_info=(f.type, f.value, f.getTracebackObject()),  # type: ignore[arg-type]
        )

    if isinstance(error_template, str):
        body = error_template.format(code=code, msg=html.escape(msg))
    else:
        body = error_template.render(code=code, msg=msg)

    respond_with_html(request, code, body)


def wrap_async_request_handler(
    h: Callable[["_AsyncResource", SynapseRequest], Awaitable[None]]
) -> Callable[["_AsyncResource", SynapseRequest], "defer.Deferred[None]"]:
    """Wraps an async request handler so that it calls request.processing.

    This helps ensure that work done by the request handler after the request is completed
    is correctly recorded against the request metrics/logs.

    The handler method must have a signature of "handle_foo(self, request)",
    where "request" must be a SynapseRequest.

    The handler may return a deferred, in which case the completion of the request isn't
    logged until the deferred completes.
    """

    async def wrapped_async_request_handler(
        self: "_AsyncResource", request: SynapseRequest
    ) -> None:
        with request.processing():
            await h(self, request)

    # we need to preserve_fn here, because the synchronous render method won't yield for
    # us (obviously)
    return preserve_fn(wrapped_async_request_handler)


# Type of a callback method for processing requests
# it is actually called with a SynapseRequest and a kwargs dict for the params,
# but I can't figure out how to represent that.
ServletCallback = Callable[
    ..., Union[None, Awaitable[None], Tuple[int, Any], Awaitable[Tuple[int, Any]]]
]


class HttpServer(Protocol):
    """Interface for registering callbacks on a HTTP server"""

    def register_paths(
        self,
        method: str,
        path_patterns: Iterable[Pattern],
        callback: ServletCallback,
        servlet_classname: str,
    ) -> None:
        """Register a callback that gets fired if we receive a http request
        with the given method for a path that matches the given regex.

        If the regex contains groups these gets passed to the callback via
        an unpacked tuple.

        The callback may be marked with the `@cancellable` decorator, which will
        cause request processing to be cancelled when clients disconnect early.

        Args:
            method: The HTTP method to listen to.
            path_patterns: The regex used to match requests.
            callback: The function to fire if we receive a matched
                request. The first argument will be the request object and
                subsequent arguments will be any matched groups from the regex.
                This should return either tuple of (code, response), or None.
            servlet_classname (str): The name of the handler to be used in prometheus
                and opentracing logs.
        """


class _AsyncResource(resource.Resource, metaclass=abc.ABCMeta):
    """Base class for resources that have async handlers.

    Sub classes can either implement `_async_render_<METHOD>` to handle
    requests by method, or override `_async_render` to handle all requests.

    Args:
        extract_context: Whether to attempt to extract the opentracing
            context from the request the servlet is handling.
    """

    def __init__(self, extract_context: bool = False):
        super().__init__()

        self._extract_context = extract_context

    def render(self, request: SynapseRequest) -> int:
        """This gets called by twisted every time someone sends us a request."""
        request.render_deferred = defer.ensureDeferred(
            self._async_render_wrapper(request)
        )
        return NOT_DONE_YET

    @wrap_async_request_handler
    async def _async_render_wrapper(self, request: SynapseRequest) -> None:
        """This is a wrapper that delegates to `_async_render` and handles
        exceptions, return values, metrics, etc.
        """
        try:
            request.request_metrics.name = self.__class__.__name__

            with trace_servlet(request, self._extract_context):
                callback_return = await self._async_render(request)

                if callback_return is not None:
                    code, response = callback_return
                    self._send_response(request, code, response)
        except Exception:
            # failure.Failure() fishes the original Failure out
            # of our stack, and thus gives us a sensible stack
            # trace.
            f = failure.Failure()
            self._send_error_response(f, request)

    async def _async_render(self, request: SynapseRequest) -> Optional[Tuple[int, Any]]:
        """Delegates to `_async_render_<METHOD>` methods, or returns a 400 if
        no appropriate method exists. Can be overridden in sub classes for
        different routing.
        """
        # Treat HEAD requests as GET requests.
        request_method = request.method.decode("ascii")
        if request_method == "HEAD":
            request_method = "GET"

        method_handler = getattr(self, "_async_render_%s" % (request_method,), None)
        if method_handler:
            request.is_render_cancellable = is_method_cancellable(method_handler)

            raw_callback_return = method_handler(request)

            # Is it synchronous? We'll allow this for now.
            if isawaitable(raw_callback_return):
                callback_return = await raw_callback_return
            else:
                callback_return = raw_callback_return

            return callback_return

        _unrecognised_request_handler(request)

    @abc.abstractmethod
    def _send_response(
        self,
        request: SynapseRequest,
        code: int,
        response_object: Any,
    ) -> None:
        raise NotImplementedError()

    @abc.abstractmethod
    def _send_error_response(
        self,
        f: failure.Failure,
        request: SynapseRequest,
    ) -> None:
        raise NotImplementedError()


class DirectServeJsonResource(_AsyncResource):
    """A resource that will call `self._async_on_<METHOD>` on new requests,
    formatting responses and errors as JSON.
    """

    def __init__(self, canonical_json: bool = False, extract_context: bool = False):
        super().__init__(extract_context)
        self.canonical_json = canonical_json

    def _send_response(
        self,
        request: SynapseRequest,
        code: int,
        response_object: Any,
    ) -> None:
        """Implements _AsyncResource._send_response"""
        # TODO: Only enable CORS for the requests that need it.
        respond_with_json(
            request,
            code,
            response_object,
            send_cors=True,
            canonical_json=self.canonical_json,
        )

    def _send_error_response(
        self,
        f: failure.Failure,
        request: SynapseRequest,
    ) -> None:
        """Implements _AsyncResource._send_error_response"""
        return_json_error(f, request)


@attr.s(slots=True, frozen=True, auto_attribs=True)
class _PathEntry:
    pattern: Pattern
    callback: ServletCallback
    servlet_classname: str


class JsonResource(DirectServeJsonResource):
    """This implements the HttpServer interface and provides JSON support for
    Resources.

    Register callbacks via register_paths()

    Callbacks can return a tuple of status code and a dict in which case the
    the dict will automatically be sent to the client as a JSON object.

    The JsonResource is primarily intended for returning JSON, but callbacks
    may send something other than JSON, they may do so by using the methods
    on the request object and instead returning None.
    """

    isLeaf = True

    def __init__(
        self,
        hs: "HomeServer",
        canonical_json: bool = True,
        extract_context: bool = False,
    ):
        super().__init__(canonical_json, extract_context)
        self.clock = hs.get_clock()
        self.path_regexs: Dict[bytes, List[_PathEntry]] = {}
        self.hs = hs

    def register_paths(
        self,
        method: str,
        path_patterns: Iterable[Pattern],
        callback: ServletCallback,
        servlet_classname: str,
    ) -> None:
        """
        Registers a request handler against a regular expression. Later request URLs are
        checked against these regular expressions in order to identify an appropriate
        handler for that request.

        Args:
            method: GET, POST etc

            path_patterns: A list of regular expressions to which the request
                URLs are compared.

            callback: The handler for the request. Usually a Servlet

            servlet_classname: The name of the handler to be used in prometheus
                and opentracing logs.
        """
        method_bytes = method.encode("utf-8")

        for path_pattern in path_patterns:
            logger.debug("Registering for %s %s", method, path_pattern.pattern)
            self.path_regexs.setdefault(method_bytes, []).append(
                _PathEntry(path_pattern, callback, servlet_classname)
            )

    def _get_handler_for_request(
        self, request: SynapseRequest
    ) -> Tuple[ServletCallback, str, Dict[str, str]]:
        """Finds a callback method to handle the given request.

        Returns:
            A tuple of the callback to use, the name of the servlet, and the
            key word arguments to pass to the callback
        """
        # At this point the path must be bytes.
        request_path_bytes: bytes = request.path  # type: ignore
        request_path = request_path_bytes.decode("ascii")
        # Treat HEAD requests as GET requests.
        request_method = request.method
        if request_method == b"HEAD":
            request_method = b"GET"

        # Loop through all the registered callbacks to check if the method
        # and path regex match
        for path_entry in self.path_regexs.get(request_method, []):
            m = path_entry.pattern.match(request_path)
            if m:
                # We found a match!
                return path_entry.callback, path_entry.servlet_classname, m.groupdict()

        # Huh. No one wanted to handle that? Fiiiiiine. Send 400.
        return _unrecognised_request_handler, "unrecognised_request_handler", {}

    async def _async_render(self, request: SynapseRequest) -> Tuple[int, Any]:
        callback, servlet_classname, group_dict = self._get_handler_for_request(request)

        request.is_render_cancellable = is_method_cancellable(callback)

        # Make sure we have an appropriate name for this handler in prometheus
        # (rather than the default of JsonResource).
        request.request_metrics.name = servlet_classname

        # Now trigger the callback. If it returns a response, we send it
        # here. If it throws an exception, that is handled by the wrapper
        # installed by @request_handler.
        kwargs = intern_dict(
            {
                name: urllib.parse.unquote(value) if value else value
                for name, value in group_dict.items()
            }
        )

        raw_callback_return = callback(request, **kwargs)

        # Is it synchronous? We'll allow this for now.
        if isinstance(raw_callback_return, (defer.Deferred, types.CoroutineType)):
            callback_return = await raw_callback_return
        else:
            callback_return = raw_callback_return

        return callback_return


class DirectServeHtmlResource(_AsyncResource):
    """A resource that will call `self._async_on_<METHOD>` on new requests,
    formatting responses and errors as HTML.
    """

    # The error template to use for this resource
    ERROR_TEMPLATE = HTML_ERROR_TEMPLATE

    def _send_response(
        self,
        request: SynapseRequest,
        code: int,
        response_object: Any,
    ) -> None:
        """Implements _AsyncResource._send_response"""
        # We expect to get bytes for us to write
        assert isinstance(response_object, bytes)
        html_bytes = response_object

        respond_with_html_bytes(request, 200, html_bytes)

    def _send_error_response(
        self,
        f: failure.Failure,
        request: SynapseRequest,
    ) -> None:
        """Implements _AsyncResource._send_error_response"""
        return_html_error(f, request, self.ERROR_TEMPLATE)


class StaticResource(File):
    """
    A resource that represents a plain non-interpreted file or directory.

    Differs from the File resource by adding clickjacking protection.
    """

    def render_GET(self, request: Request) -> bytes:
        set_clickjacking_protection_headers(request)
        return super().render_GET(request)


def _unrecognised_request_handler(request: Request) -> NoReturn:
    """Request handler for unrecognised requests

    This is a request handler suitable for return from
    _get_handler_for_request. It actually just raises an
    UnrecognizedRequestError.

    Args:
        request: Unused, but passed in to match the signature of ServletCallback.
    """
    raise UnrecognizedRequestError()


class RootRedirect(resource.Resource):
    """Redirects the root '/' path to another path."""

    def __init__(self, path: str):
        super().__init__()
        self.url = path

    def render_GET(self, request: Request) -> bytes:
        return redirectTo(self.url.encode("ascii"), request)

    def getChild(self, name: str, request: Request) -> resource.Resource:
        if len(name) == 0:
            return self  # select ourselves as the child to render
        return super().getChild(name, request)


class OptionsResource(resource.Resource):
    """Responds to OPTION requests for itself and all children."""

    def render_OPTIONS(self, request: Request) -> bytes:
        request.setResponseCode(204)
        request.setHeader(b"Content-Length", b"0")

        set_cors_headers(request)

        return b""

    def getChildWithDefault(self, path: str, request: Request) -> resource.Resource:
        if request.method == b"OPTIONS":
            return self  # select ourselves as the child to render
        return super().getChildWithDefault(path, request)


class RootOptionsRedirectResource(OptionsResource, RootRedirect):
    pass


@implementer(interfaces.IPushProducer)
class _ByteProducer:
    """
    Iteratively write bytes to the request.
    """

    # The minimum number of bytes for each chunk. Note that the last chunk will
    # usually be smaller than this.
    min_chunk_size = 1024

    def __init__(
        self,
        request: Request,
        iterator: Iterator[bytes],
    ):
        self._request: Optional[Request] = request
        self._iterator = iterator
        self._paused = False

        try:
            self._request.registerProducer(self, True)
        except AttributeError as e:
            # Calling self._request.registerProducer might raise an AttributeError since
            # the underlying Twisted code calls self._request.channel.registerProducer,
            # however self._request.channel will be None if the connection was lost.
            logger.info("Connection disconnected before response was written: %r", e)

            # We drop our references to data we'll not use.
            self._request = None
            self._iterator = iter(())
        else:
            # Start producing if `registerProducer` was successful
            self.resumeProducing()

    def _send_data(self, data: List[bytes]) -> None:
        """
        Send a list of bytes as a chunk of a response.
        """
        if not data or not self._request:
            return
        self._request.write(b"".join(data))

    def pauseProducing(self) -> None:
        self._paused = True

    def resumeProducing(self) -> None:
        # We've stopped producing in the meantime (note that this might be
        # re-entrant after calling write).
        if not self._request:
            return

        self._paused = False

        # Write until there's backpressure telling us to stop.
        while not self._paused:
            # Get the next chunk and write it to the request.
            #
            # The output of the JSON encoder is buffered and coalesced until
            # min_chunk_size is reached. This is because JSON encoders produce
            # very small output per iteration and the Request object converts
            # each call to write() to a separate chunk. Without this there would
            # be an explosion in bytes written (e.g. b"{" becoming "1\r\n{\r\n").
            #
            # Note that buffer stores a list of bytes (instead of appending to
            # bytes) to hopefully avoid many allocations.
            buffer = []
            buffered_bytes = 0
            while buffered_bytes < self.min_chunk_size:
                try:
                    data = next(self._iterator)
                    buffer.append(data)
                    buffered_bytes += len(data)
                except StopIteration:
                    # The entire JSON object has been serialized, write any
                    # remaining data, finalize the producer and the request, and
                    # clean-up any references.
                    self._send_data(buffer)
                    self._request.unregisterProducer()
                    self._request.finish()
                    self.stopProducing()
                    return

            self._send_data(buffer)

    def stopProducing(self) -> None:
        # Clear a circular reference.
        self._request = None


def _encode_json_bytes(json_object: Any) -> bytes:
    """
    Encode an object into JSON. Returns an iterator of bytes.
    """
    return json_encoder.encode(json_object).encode("utf-8")


def respond_with_json(
    request: SynapseRequest,
    code: int,
    json_object: Any,
    send_cors: bool = False,
    canonical_json: bool = True,
) -> Optional[int]:
    """Sends encoded JSON in response to the given request.

    Args:
        request: The http request to respond to.
        code: The HTTP response code.
        json_object: The object to serialize to JSON.
        send_cors: Whether to send Cross-Origin Resource Sharing headers
            https://fetch.spec.whatwg.org/#http-cors-protocol
        canonical_json: Whether to use the canonicaljson algorithm when encoding
            the JSON bytes.

    Returns:
        twisted.web.server.NOT_DONE_YET if the request is still active.
    """
    # The response code must always be set, for logging purposes.
    request.setResponseCode(code)

    # could alternatively use request.notifyFinish() and flip a flag when
    # the Deferred fires, but since the flag is RIGHT THERE it seems like
    # a waste.
    if request._disconnected:
        logger.warning(
            "Not sending response to request %s, already disconnected.", request
        )
        return None

    if canonical_json:
        encoder = encode_canonical_json
    else:
        encoder = _encode_json_bytes

    request.setHeader(b"Content-Type", b"application/json")
    request.setHeader(b"Cache-Control", b"no-cache, no-store, must-revalidate")

    if send_cors:
        set_cors_headers(request)

    run_in_background(
        _async_write_json_to_request_in_thread, request, encoder, json_object
    )
    return NOT_DONE_YET


def respond_with_json_bytes(
    request: Request,
    code: int,
    json_bytes: bytes,
    send_cors: bool = False,
) -> Optional[int]:
    """Sends encoded JSON in response to the given request.

    Args:
        request: The http request to respond to.
        code: The HTTP response code.
        json_bytes: The json bytes to use as the response body.
        send_cors: Whether to send Cross-Origin Resource Sharing headers
            https://fetch.spec.whatwg.org/#http-cors-protocol

    Returns:
        twisted.web.server.NOT_DONE_YET if the request is still active.
    """
    # The response code must always be set, for logging purposes.
    request.setResponseCode(code)

    if request._disconnected:
        logger.warning(
            "Not sending response to request %s, already disconnected.", request
        )
        return None

    request.setHeader(b"Content-Type", b"application/json")
    request.setHeader(b"Content-Length", b"%d" % (len(json_bytes),))
    request.setHeader(b"Cache-Control", b"no-cache, no-store, must-revalidate")

    if send_cors:
        set_cors_headers(request)

    _write_bytes_to_request(request, json_bytes)
    return NOT_DONE_YET


async def _async_write_json_to_request_in_thread(
    request: SynapseRequest,
    json_encoder: Callable[[Any], bytes],
    json_object: Any,
) -> None:
    """Encodes the given JSON object on a thread and then writes it to the
    request.

    This is done so that encoding large JSON objects doesn't block the reactor
    thread.

    Note: We don't use JsonEncoder.iterencode here as that falls back to the
    Python implementation (rather than the C backend), which is *much* more
    expensive.
    """

    def encode(opentracing_span: "Optional[opentracing.Span]") -> bytes:
        # it might take a while for the threadpool to schedule us, so we write
        # opentracing logs once we actually get scheduled, so that we can see how
        # much that contributed.
        if opentracing_span:
            opentracing_span.log_kv({"event": "scheduled"})
        res = json_encoder(json_object)
        if opentracing_span:
            opentracing_span.log_kv({"event": "encoded"})
        return res

    with start_active_span("encode_json_response"):
        span = active_span()
        json_str = await defer_to_thread(request.reactor, encode, span)

    _write_bytes_to_request(request, json_str)


def _write_bytes_to_request(request: Request, bytes_to_write: bytes) -> None:
    """Writes the bytes to the request using an appropriate producer.

    Note: This should be used instead of `Request.write` to correctly handle
    large response bodies.
    """

    # The problem with dumping all of the response into the `Request` object at
    # once (via `Request.write`) is that doing so starts the timeout for the
    # next request to be received: so if it takes longer than 60s to stream back
    # the response to the client, the client never gets it.
    #
    # The correct solution is to use a Producer; then the timeout is only
    # started once all of the content is sent over the TCP connection.

    # To make sure we don't write all of the bytes at once we split it up into
    # chunks.
    chunk_size = 4096
    bytes_generator = chunk_seq(bytes_to_write, chunk_size)

    # We use a `_ByteProducer` here rather than `NoRangeStaticProducer` as the
    # unit tests can't cope with being given a pull producer.
    _ByteProducer(request, bytes_generator)


def set_cors_headers(request: Request) -> None:
    """Set the CORS headers so that javascript running in a web browsers can
    use this API

    Args:
        request: The http request to add CORS to.
    """
    request.setHeader(b"Access-Control-Allow-Origin", b"*")
    request.setHeader(
        b"Access-Control-Allow-Methods", b"GET, HEAD, POST, PUT, DELETE, OPTIONS"
    )
    request.setHeader(
        b"Access-Control-Allow-Headers",
        b"X-Requested-With, Content-Type, Authorization, Date",
    )


def set_corp_headers(request: Request) -> None:
    """Set the CORP headers so that javascript running in a web browsers can
    embed the resource returned from this request when their client requires
    the `Cross-Origin-Embedder-Policy: require-corp` header.

    Args:
        request: The http request to add the CORP header to.
    """
    request.setHeader(b"Cross-Origin-Resource-Policy", b"cross-origin")


def respond_with_html(request: Request, code: int, html: str) -> None:
    """
    Wraps `respond_with_html_bytes` by first encoding HTML from a str to UTF-8 bytes.
    """
    respond_with_html_bytes(request, code, html.encode("utf-8"))


def respond_with_html_bytes(request: Request, code: int, html_bytes: bytes) -> None:
    """
    Sends HTML (encoded as UTF-8 bytes) as the response to the given request.

    Note that this adds clickjacking protection headers and finishes the request.

    Args:
        request: The http request to respond to.
        code: The HTTP response code.
        html_bytes: The HTML bytes to use as the response body.
    """
    # The response code must always be set, for logging purposes.
    request.setResponseCode(code)

    # could alternatively use request.notifyFinish() and flip a flag when
    # the Deferred fires, but since the flag is RIGHT THERE it seems like
    # a waste.
    if request._disconnected:
        logger.warning(
            "Not sending response to request %s, already disconnected.", request
        )
        return None

    request.setHeader(b"Content-Type", b"text/html; charset=utf-8")
    request.setHeader(b"Content-Length", b"%d" % (len(html_bytes),))

    # Ensure this content cannot be embedded.
    set_clickjacking_protection_headers(request)

    request.write(html_bytes)
    finish_request(request)


def set_clickjacking_protection_headers(request: Request) -> None:
    """
    Set headers to guard against clickjacking of embedded content.

    This sets the X-Frame-Options and Content-Security-Policy headers which instructs
    browsers to not allow the HTML of the response to be embedded onto another
    page.

    Args:
        request: The http request to add the headers to.
    """
    request.setHeader(b"X-Frame-Options", b"DENY")
    request.setHeader(b"Content-Security-Policy", b"frame-ancestors 'none';")


def respond_with_redirect(request: Request, url: bytes) -> None:
    """Write a 302 response to the request, if it is still alive."""
    logger.debug("Redirect to %s", url.decode("utf-8"))
    request.redirect(url)
    finish_request(request)


def finish_request(request: Request) -> None:
    """Finish writing the response to the request.

    Twisted throws a RuntimeException if the connection closed before the
    response was written but doesn't provide a convenient or reliable way to
    determine if the connection was closed. So we catch and log the RuntimeException

    You might think that ``request.notifyFinish`` could be used to tell if the
    request was finished. However the deferred it returns won't fire if the
    connection was already closed, meaning we'd have to have called the method
    right at the start of the request. By the time we want to write the response
    it will already be too late.
    """
    try:
        request.finish()
    except RuntimeError as e:
        logger.info("Connection disconnected before response was written: %r", e)
