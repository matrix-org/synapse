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


from synapse.api.errors import (
    cs_exception, SynapseError, CodeMessageException, UnrecognizedRequestError, Codes
)
from synapse.http.request_metrics import (
    requests_counter,
)
from synapse.util.logcontext import LoggingContext, PreserveLoggingContext
from synapse.util.caches import intern_dict
from synapse.util.metrics import Measure
import synapse.metrics
import synapse.events

from canonicaljson import (
    encode_canonical_json, encode_pretty_printed_json
)

from twisted.internet import defer
from twisted.python import failure
from twisted.web import server, resource
from twisted.web.server import NOT_DONE_YET
from twisted.web.util import redirectTo

import collections
import logging
import urllib
import simplejson

logger = logging.getLogger(__name__)


def wrap_json_request_handler(h):
    """Wraps a request handler method with exception handling.

    Also adds logging as per wrap_request_handler_with_logging.

    The handler method must have a signature of "handle_foo(self, request)",
    where "self" must have a "clock" attribute (and "request" must be a
    SynapseRequest).

    The handler must return a deferred. If the deferred succeeds we assume that
    a response has been sent. If the deferred fails with a SynapseError we use
    it to send a JSON response with the appropriate HTTP reponse code. If the
    deferred fails with any other type of error we send a 500 reponse.
    """

    @defer.inlineCallbacks
    def wrapped_request_handler(self, request):
        try:
            yield h(self, request)
        except CodeMessageException as e:
            code = e.code
            if isinstance(e, SynapseError):
                logger.info(
                    "%s SynapseError: %s - %s", request, code, e.msg
                )
            else:
                logger.exception(e)
            respond_with_json(
                request, code, cs_exception(e), send_cors=True,
                pretty_print=_request_user_agent_is_curl(request),
            )

        except Exception:
            # failure.Failure() fishes the original Failure out
            # of our stack, and thus gives us a sensible stack
            # trace.
            f = failure.Failure()
            logger.error(
                "Failed handle request via %r: %r: %s",
                h,
                request,
                f.getTraceback().rstrip(),
            )
            respond_with_json(
                request,
                500,
                {
                    "error": "Internal server error",
                    "errcode": Codes.UNKNOWN,
                },
                send_cors=True,
                pretty_print=_request_user_agent_is_curl(request),
            )

    return wrap_request_handler_with_logging(wrapped_request_handler)


def wrap_request_handler_with_logging(h):
    """Wraps a request handler to provide logging and metrics

    The handler method must have a signature of "handle_foo(self, request)",
    where "self" must have a "clock" attribute (and "request" must be a
    SynapseRequest).

    As well as calling `request.processing` (which will log the response and
    duration for this request), the wrapped request handler will insert the
    request id into the logging context.
    """
    @defer.inlineCallbacks
    def wrapped_request_handler(self, request):
        """
        Args:
            self:
            request (synapse.http.site.SynapseRequest):
        """

        request_id = request.get_request_id()
        with LoggingContext(request_id) as request_context:
            request_context.request = request_id
            with Measure(self.clock, "wrapped_request_handler"):
                # we start the request metrics timer here with an initial stab
                # at the servlet name. For most requests that name will be
                # JsonResource (or a subclass), and JsonResource._async_render
                # will update it once it picks a servlet.
                servlet_name = self.__class__.__name__
                with request.processing(servlet_name):
                    with PreserveLoggingContext(request_context):
                        d = h(self, request)

                        # record the arrival of the request *after*
                        # dispatching to the handler, so that the handler
                        # can update the servlet name in the request
                        # metrics
                        requests_counter.inc(request.method,
                                             request.request_metrics.name)
                        yield d
    return wrapped_request_handler


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

    _PathEntry = collections.namedtuple("_PathEntry", ["pattern", "callback"])

    def __init__(self, hs, canonical_json=True):
        resource.Resource.__init__(self)

        self.canonical_json = canonical_json
        self.clock = hs.get_clock()
        self.path_regexs = {}
        self.hs = hs

    def register_paths(self, method, path_patterns, callback):
        for path_pattern in path_patterns:
            logger.debug("Registering for %s %s", method, path_pattern.pattern)
            self.path_regexs.setdefault(method, []).append(
                self._PathEntry(path_pattern, callback)
            )

    def render(self, request):
        """ This gets called by twisted every time someone sends us a request.
        """
        self._async_render(request)
        return server.NOT_DONE_YET

    @wrap_json_request_handler
    @defer.inlineCallbacks
    def _async_render(self, request):
        """ This gets called from render() every time someone sends us a request.
            This checks if anyone has registered a callback for that method and
            path.
        """
        callback, group_dict = self._get_handler_for_request(request)

        servlet_instance = getattr(callback, "__self__", None)
        if servlet_instance is not None:
            servlet_classname = servlet_instance.__class__.__name__
        else:
            servlet_classname = "%r" % callback
        request.request_metrics.name = servlet_classname

        # Now trigger the callback. If it returns a response, we send it
        # here. If it throws an exception, that is handled by the wrapper
        # installed by @request_handler.

        kwargs = intern_dict({
            name: urllib.unquote(value).decode("UTF-8") if value else value
            for name, value in group_dict.items()
        })

        callback_return = yield callback(request, **kwargs)
        if callback_return is not None:
            code, response = callback_return
            self._send_response(request, code, response)

    def _get_handler_for_request(self, request):
        """Finds a callback method to handle the given request

        Args:
            request (twisted.web.http.Request):

        Returns:
            Tuple[Callable, dict[str, str]]: callback method, and the dict
                mapping keys to path components as specified in the handler's
                path match regexp.

                The callback will normally be a method registered via
                register_paths, so will return (possibly via Deferred) either
                None, or a tuple of (http code, response body).
        """
        if request.method == b"OPTIONS":
            return _options_handler, {}

        # Loop through all the registered callbacks to check if the method
        # and path regex match
        for path_entry in self.path_regexs.get(request.method, []):
            m = path_entry.pattern.match(request.path)
            if m:
                # We found a match!
                return path_entry.callback, m.groupdict()

        # Huh. No one wanted to handle that? Fiiiiiine. Send 400.
        return _unrecognised_request_handler, {}

    def _send_response(self, request, code, response_json_object,
                       response_code_message=None):
        # TODO: Only enable CORS for the requests that need it.
        respond_with_json(
            request, code, response_json_object,
            send_cors=True,
            response_code_message=response_code_message,
            pretty_print=_request_user_agent_is_curl(request),
            canonical_json=self.canonical_json,
        )


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
        return redirectTo(self.url, request)

    def getChild(self, name, request):
        if len(name) == 0:
            return self  # select ourselves as the child to render
        return resource.Resource.getChild(self, name, request)


def respond_with_json(request, code, json_object, send_cors=False,
                      response_code_message=None, pretty_print=False,
                      canonical_json=True):
    # could alternatively use request.notifyFinish() and flip a flag when
    # the Deferred fires, but since the flag is RIGHT THERE it seems like
    # a waste.
    if request._disconnected:
        logger.warn(
            "Not sending response to request %s, already disconnected.",
            request)
        return

    if pretty_print:
        json_bytes = encode_pretty_printed_json(json_object) + "\n"
    else:
        if canonical_json or synapse.events.USE_FROZEN_DICTS:
            json_bytes = encode_canonical_json(json_object)
        else:
            json_bytes = simplejson.dumps(json_object)

    return respond_with_json_bytes(
        request, code, json_bytes,
        send_cors=send_cors,
        response_code_message=response_code_message,
    )


def respond_with_json_bytes(request, code, json_bytes, send_cors=False,
                            response_code_message=None):
    """Sends encoded JSON in response to the given request.

    Args:
        request (twisted.web.http.Request): The http request to respond to.
        code (int): The HTTP response code.
        json_bytes (bytes): The json bytes to use as the response body.
        send_cors (bool): Whether to send Cross-Origin Resource Sharing headers
            http://www.w3.org/TR/cors/
    Returns:
        twisted.web.server.NOT_DONE_YET"""

    request.setResponseCode(code, message=response_code_message)
    request.setHeader(b"Content-Type", b"application/json")
    request.setHeader(b"Content-Length", b"%d" % (len(json_bytes),))
    request.setHeader(b"Cache-Control", b"no-cache, no-store, must-revalidate")

    if send_cors:
        set_cors_headers(request)

    request.write(json_bytes)
    finish_request(request)
    return NOT_DONE_YET


def set_cors_headers(request):
    """Set the CORs headers so that javascript running in a web browsers can
    use this API

    Args:
        request (twisted.web.http.Request): The http request to add CORs to.
    """
    request.setHeader("Access-Control-Allow-Origin", "*")
    request.setHeader(
        "Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS"
    )
    request.setHeader(
        "Access-Control-Allow-Headers",
        "Origin, X-Requested-With, Content-Type, Accept, Authorization"
    )


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
    user_agents = request.requestHeaders.getRawHeaders(
        b"User-Agent", default=[]
    )
    for user_agent in user_agents:
        if b"curl" in user_agent:
            return True
    return False
