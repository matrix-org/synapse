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

import collections
import html
import http.client
import logging
import types
import urllib
from io import BytesIO
from typing import Awaitable, Callable, TypeVar, Union

import jinja2
from canonicaljson import encode_canonical_json, encode_pretty_printed_json, json

from twisted.internet import defer
from twisted.python import failure
from twisted.web import resource
from twisted.web.server import NOT_DONE_YET, Request
from twisted.web.static import File, NoRangeStaticProducer
from twisted.web.util import redirectTo

import synapse.events
import synapse.metrics
from synapse.api.errors import (
    CodeMessageException,
    Codes,
    RedirectException,
    SynapseError,
    UnrecognizedRequestError,
)
from synapse.http.site import SynapseRequest
from synapse.logging.context import preserve_fn
from synapse.logging.opentracing import trace_servlet
from synapse.util.caches import intern_dict

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


def wrap_json_request_handler(h):
    """Wraps a request handler method with exception handling.

    Also does the wrapping with request.processing as per wrap_async_request_handler.

    The handler method must have a signature of "handle_foo(self, request)",
    where "request" must be a SynapseRequest.

    The handler must return a deferred or a coroutine. If the deferred succeeds
    we assume that a response has been sent. If the deferred fails with a SynapseError we use
    it to send a JSON response with the appropriate HTTP reponse code. If the
    deferred fails with any other type of error we send a 500 reponse.
    """

    async def wrapped_request_handler(self, request):
        try:
            await h(self, request)
        except SynapseError as e:
            code = e.code
            logger.info("%s SynapseError: %s - %s", request, code, e.msg)

            # Only respond with an error response if we haven't already started
            # writing, otherwise lets just kill the connection
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
                    code,
                    e.error_dict(),
                    send_cors=True,
                    pretty_print=_request_user_agent_is_curl(request),
                )

        except Exception:
            # failure.Failure() fishes the original Failure out
            # of our stack, and thus gives us a sensible stack
            # trace.
            f = failure.Failure()
            logger.error(
                "Failed handle request via %r: %r",
                request.request_metrics.name,
                request,
                exc_info=(f.type, f.value, f.getTracebackObject()),
            )
            # Only respond with an error response if we haven't already started
            # writing, otherwise lets just kill the connection
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
                    500,
                    {"error": "Internal server error", "errcode": Codes.UNKNOWN},
                    send_cors=True,
                    pretty_print=_request_user_agent_is_curl(request),
                )

    return wrap_async_request_handler(wrapped_request_handler)


TV = TypeVar("TV")


def wrap_html_request_handler(
    h: Callable[[TV, SynapseRequest], Awaitable]
) -> Callable[[TV, SynapseRequest], Awaitable[None]]:
    """Wraps a request handler method with exception handling.

    Also does the wrapping with request.processing as per wrap_async_request_handler.

    The handler method must have a signature of "handle_foo(self, request)",
    where "request" must be a SynapseRequest.
    """

    async def wrapped_request_handler(self, request):
        try:
            await h(self, request)
        except Exception:
            f = failure.Failure()
            return_html_error(f, request, HTML_ERROR_TEMPLATE)

    return wrap_async_request_handler(wrapped_request_handler)


def return_html_error(
    f: failure.Failure, request: Request, error_template: Union[str, jinja2.Template],
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
        cme = f.value
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
                exc_info=(f.type, f.value, f.getTracebackObject()),
            )
    else:
        code = http.HTTPStatus.INTERNAL_SERVER_ERROR
        msg = "Internal server error"

        logger.error(
            "Failed handle request %r",
            request,
            exc_info=(f.type, f.value, f.getTracebackObject()),
        )

    if isinstance(error_template, str):
        body = error_template.format(code=code, msg=html.escape(msg))
    else:
        body = error_template.render(code=code, msg=msg)

    respond_with_html(request, code, body)


def wrap_async_request_handler(h):
    """Wraps an async request handler so that it calls request.processing.

    This helps ensure that work done by the request handler after the request is completed
    is correctly recorded against the request metrics/logs.

    The handler method must have a signature of "handle_foo(self, request)",
    where "request" must be a SynapseRequest.

    The handler may return a deferred, in which case the completion of the request isn't
    logged until the deferred completes.
    """

    async def wrapped_async_request_handler(self, request):
        with request.processing():
            await h(self, request)

    # we need to preserve_fn here, because the synchronous render method won't yield for
    # us (obviously)
    return preserve_fn(wrapped_async_request_handler)


class HttpServer(object):
    """ Interface for registering callbacks on a HTTP server
    """

    def register_paths(self, method, path_patterns, callback):
        """ Register a callback that gets fired if we receive a http request
        with the given method for a path that matches the given regex.

        If the regex contains groups these gets passed to the calback via
        an unpacked tuple.

        Args:
            method (str): The method to listen to.
            path_patterns (list<SRE_Pattern>): The regex used to match requests.
            callback (function): The function to fire if we receive a matched
                request. The first argument will be the request object and
                subsequent arguments will be any matched groups from the regex.
                This should return a tuple of (code, response).
        """
        pass


class JsonResource(HttpServer, resource.Resource):
    """ This implements the HttpServer interface and provides JSON support for
    Resources.

    Register callbacks via register_paths()

    Callbacks can return a tuple of status code and a dict in which case the
    the dict will automatically be sent to the client as a JSON object.

    The JsonResource is primarily intended for returning JSON, but callbacks
    may send something other than JSON, they may do so by using the methods
    on the request object and instead returning None.
    """

    isLeaf = True

    _PathEntry = collections.namedtuple(
        "_PathEntry", ["pattern", "callback", "servlet_classname"]
    )

    def __init__(self, hs, canonical_json=True):
        resource.Resource.__init__(self)

        self.canonical_json = canonical_json
        self.clock = hs.get_clock()
        self.path_regexs = {}
        self.hs = hs

    def register_paths(
        self, method, path_patterns, callback, servlet_classname, trace=True
    ):
        """
        Registers a request handler against a regular expression. Later request URLs are
        checked against these regular expressions in order to identify an appropriate
        handler for that request.

        Args:
            method (str): GET, POST etc

            path_patterns (Iterable[str]): A list of regular expressions to which
                the request URLs are compared.

            callback (function): The handler for the request. Usually a Servlet

            servlet_classname (str): The name of the handler to be used in prometheus
                and opentracing logs.

            trace (bool): Whether we should start a span to trace the servlet.
        """
        method = method.encode("utf-8")  # method is bytes on py3

        if trace:
            # We don't extract the context from the servlet because we can't
            # trust the sender
            callback = trace_servlet(servlet_classname)(callback)

        for path_pattern in path_patterns:
            logger.debug("Registering for %s %s", method, path_pattern.pattern)
            self.path_regexs.setdefault(method, []).append(
                self._PathEntry(path_pattern, callback, servlet_classname)
            )

    def render(self, request):
        """ This gets called by twisted every time someone sends us a request.
        """
        defer.ensureDeferred(self._async_render(request))
        return NOT_DONE_YET

    @wrap_json_request_handler
    async def _async_render(self, request):
        """ This gets called from render() every time someone sends us a request.
            This checks if anyone has registered a callback for that method and
            path.
        """
        callback, servlet_classname, group_dict = self._get_handler_for_request(request)

        # Make sure we have a name for this handler in prometheus.
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

        callback_return = callback(request, **kwargs)

        # Is it synchronous? We'll allow this for now.
        if isinstance(callback_return, (defer.Deferred, types.CoroutineType)):
            callback_return = await callback_return

        if callback_return is not None:
            code, response = callback_return
            self._send_response(request, code, response)

    def _get_handler_for_request(self, request):
        """Finds a callback method to handle the given request

        Args:
            request (twisted.web.http.Request):

        Returns:
            Tuple[Callable, str, dict[unicode, unicode]]: callback method, the
                label to use for that method in prometheus metrics, and the
                dict mapping keys to path components as specified in the
                handler's path match regexp.

                The callback will normally be a method registered via
                register_paths, so will return (possibly via Deferred) either
                None, or a tuple of (http code, response body).
        """
        request_path = request.path.decode("ascii")

        # Loop through all the registered callbacks to check if the method
        # and path regex match
        for path_entry in self.path_regexs.get(request.method, []):
            m = path_entry.pattern.match(request_path)
            if m:
                # We found a match!
                return path_entry.callback, path_entry.servlet_classname, m.groupdict()

        # Huh. No one wanted to handle that? Fiiiiiine. Send 400.
        return _unrecognised_request_handler, "unrecognised_request_handler", {}

    def _send_response(
        self, request, code, response_json_object, response_code_message=None
    ):
        # TODO: Only enable CORS for the requests that need it.
        respond_with_json(
            request,
            code,
            response_json_object,
            send_cors=True,
            response_code_message=response_code_message,
            pretty_print=_request_user_agent_is_curl(request),
            canonical_json=self.canonical_json,
        )


class DirectServeResource(resource.Resource):
    def render(self, request):
        """
        Render the request, using an asynchronous render handler if it exists.
        """
        async_render_callback_name = "_async_render_" + request.method.decode("ascii")

        # Try and get the async renderer
        callback = getattr(self, async_render_callback_name, None)

        # No async renderer for this request method.
        if not callback:
            return super().render(request)

        resp = trace_servlet(self.__class__.__name__)(callback)(request)

        # If it's a coroutine, turn it into a Deferred
        if isinstance(resp, types.CoroutineType):
            defer.ensureDeferred(resp)

        return NOT_DONE_YET


class StaticResource(File):
    """
    A resource that represents a plain non-interpreted file or directory.

    Differs from the File resource by adding clickjacking protection.
    """

    def render_GET(self, request: Request):
        set_clickjacking_protection_headers(request)
        return super().render_GET(request)


def _options_handler(request):
    """Request handler for OPTIONS requests

    This is a request handler suitable for return from
    _get_handler_for_request. It returns a 200 and an empty body.

    Args:
        request (twisted.web.http.Request):

    Returns:
        Tuple[int, dict]: http code, response body.
    """
    return 200, {}


def _unrecognised_request_handler(request):
    """Request handler for unrecognised requests

    This is a request handler suitable for return from
    _get_handler_for_request. It actually just raises an
    UnrecognizedRequestError.

    Args:
        request (twisted.web.http.Request):
    """
    raise UnrecognizedRequestError()


class RootRedirect(resource.Resource):
    """Redirects the root '/' path to another path."""

    def __init__(self, path):
        resource.Resource.__init__(self)
        self.url = path

    def render_GET(self, request):
        return redirectTo(self.url.encode("ascii"), request)

    def getChild(self, name, request):
        if len(name) == 0:
            return self  # select ourselves as the child to render
        return resource.Resource.getChild(self, name, request)


class OptionsResource(resource.Resource):
    """Responds to OPTION requests for itself and all children."""

    def render_OPTIONS(self, request):
        code, response_json_object = _options_handler(request)

        return respond_with_json(
            request, code, response_json_object, send_cors=True, canonical_json=False,
        )

    def getChildWithDefault(self, path, request):
        if request.method == b"OPTIONS":
            return self  # select ourselves as the child to render
        return resource.Resource.getChildWithDefault(self, path, request)


class RootOptionsRedirectResource(OptionsResource, RootRedirect):
    pass


def respond_with_json(
    request,
    code,
    json_object,
    send_cors=False,
    response_code_message=None,
    pretty_print=False,
    canonical_json=True,
):
    # could alternatively use request.notifyFinish() and flip a flag when
    # the Deferred fires, but since the flag is RIGHT THERE it seems like
    # a waste.
    if request._disconnected:
        logger.warning(
            "Not sending response to request %s, already disconnected.", request
        )
        return

    if pretty_print:
        json_bytes = encode_pretty_printed_json(json_object) + b"\n"
    else:
        if canonical_json or synapse.events.USE_FROZEN_DICTS:
            # canonicaljson already encodes to bytes
            json_bytes = encode_canonical_json(json_object)
        else:
            json_bytes = json.dumps(json_object).encode("utf-8")

    return respond_with_json_bytes(
        request,
        code,
        json_bytes,
        send_cors=send_cors,
        response_code_message=response_code_message,
    )


def respond_with_json_bytes(
    request, code, json_bytes, send_cors=False, response_code_message=None
):
    """Sends encoded JSON in response to the given request.

    Args:
        request (twisted.web.http.Request): The http request to respond to.
        code (int): The HTTP response code.
        json_bytes (bytes): The json bytes to use as the response body.
        send_cors (bool): Whether to send Cross-Origin Resource Sharing headers
            https://fetch.spec.whatwg.org/#http-cors-protocol
    Returns:
        twisted.web.server.NOT_DONE_YET"""

    request.setResponseCode(code, message=response_code_message)
    request.setHeader(b"Content-Type", b"application/json")
    request.setHeader(b"Content-Length", b"%d" % (len(json_bytes),))
    request.setHeader(b"Cache-Control", b"no-cache, no-store, must-revalidate")

    if send_cors:
        set_cors_headers(request)

    # todo: we can almost certainly avoid this copy and encode the json straight into
    # the bytesIO, but it would involve faffing around with string->bytes wrappers.
    bytes_io = BytesIO(json_bytes)

    producer = NoRangeStaticProducer(request, bytes_io)
    producer.start()
    return NOT_DONE_YET


def set_cors_headers(request):
    """Set the CORs headers so that javascript running in a web browsers can
    use this API

    Args:
        request (twisted.web.http.Request): The http request to add CORs to.
    """
    request.setHeader(b"Access-Control-Allow-Origin", b"*")
    request.setHeader(
        b"Access-Control-Allow-Methods", b"GET, POST, PUT, DELETE, OPTIONS"
    )
    request.setHeader(
        b"Access-Control-Allow-Headers",
        b"Origin, X-Requested-With, Content-Type, Accept, Authorization",
    )


def respond_with_html(request: Request, code: int, html: str):
    """
    Wraps `respond_with_html_bytes` by first encoding HTML from a str to UTF-8 bytes.
    """
    respond_with_html_bytes(request, code, html.encode("utf-8"))


def respond_with_html_bytes(request: Request, code: int, html_bytes: bytes):
    """
    Sends HTML (encoded as UTF-8 bytes) as the response to the given request.

    Note that this adds clickjacking protection headers and finishes the request.

    Args:
        request: The http request to respond to.
        code: The HTTP response code.
        html_bytes: The HTML bytes to use as the response body.
    """
    # could alternatively use request.notifyFinish() and flip a flag when
    # the Deferred fires, but since the flag is RIGHT THERE it seems like
    # a waste.
    if request._disconnected:
        logger.warning(
            "Not sending response to request %s, already disconnected.", request
        )
        return

    request.setResponseCode(code)
    request.setHeader(b"Content-Type", b"text/html; charset=utf-8")
    request.setHeader(b"Content-Length", b"%d" % (len(html_bytes),))

    # Ensure this content cannot be embedded.
    set_clickjacking_protection_headers(request)

    request.write(html_bytes)
    finish_request(request)


def set_clickjacking_protection_headers(request: Request):
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


def finish_request(request):
    """ Finish writing the response to the request.

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


def _request_user_agent_is_curl(request):
    user_agents = request.requestHeaders.getRawHeaders(b"User-Agent", default=[])
    for user_agent in user_agents:
        if b"curl" in user_agent:
            return True
    return False
