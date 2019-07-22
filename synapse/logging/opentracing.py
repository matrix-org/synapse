# -*- coding: utf-8 -*-
# Copyright 2019 The Matrix.org Foundation C.I.C.
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


# NOTE
# This is a small wrapper around opentracing because opentracing is not currently
# packaged downstream (specifically debian). Since opentracing instrumentation is
# fairly invasive it was awkward to make it optional. As a result we opted to encapsulate
# all opentracing state in these methods which effectively noop if opentracing is
# not present. We should strongly consider encouraging the downstream distributers
# to package opentracing and making opentracing a full dependency. In order to facilitate
# this move the methods have work very similarly to opentracing's and it should only
# be a matter of few regexes to move over to opentracing's access patterns proper.

import contextlib
import inspect
import logging
import re
from functools import wraps

from canonicaljson import json

from twisted.internet import defer

from synapse.config import ConfigError

try:
    import opentracing
except ImportError:
    opentracing = None
try:
    from jaeger_client import Config as JaegerConfig
    from synapse.logging.scopecontextmanager import LogContextScopeManager
except ImportError:
    JaegerConfig = None
    LogContextScopeManager = None


logger = logging.getLogger(__name__)


# Block everything by default
# A regex which matches the server_names to expose traces for.
# None means 'block everything'.
_homeserver_whitelist = None

# Util methods


def only_if_tracing(func):
    """Executes the function only if we're tracing. Otherwise return.
    Assumes the function wrapped may return None"""

    @wraps(func)
    def _only_if_tracing_inner(*args, **kwargs):
        if opentracing:
            return func(*args, **kwargs)
        else:
            return

    return _only_if_tracing_inner


@contextlib.contextmanager
def _noop_context_manager(*args, **kwargs):
    """Does exactly what it says on the tin"""
    yield


# Setup


def init_tracer(config):
    """Set the whitelists and initialise the JaegerClient tracer

    Args:
        config (HomeserverConfig): The config used by the homeserver
    """
    global opentracing
    if not config.opentracer_enabled:
        # We don't have a tracer
        opentracing = None
        return

    if not opentracing or not JaegerConfig:
        raise ConfigError(
            "The server has been configured to use opentracing but opentracing is not "
            "installed."
        )

    # Include the worker name
    name = config.worker_name if config.worker_name else "master"

    set_homeserver_whitelist(config.opentracer_whitelist)
    jaeger_config = JaegerConfig(
        config={"sampler": {"type": "const", "param": 1}, "logging": True},
        service_name="{} {}".format(config.server_name, name),
        scope_manager=LogContextScopeManager(config),
    )
    jaeger_config.initialize_tracer()

    # Set up tags to be opentracing's tags
    global tags
    tags = opentracing.tags


# Whitelisting


@only_if_tracing
def set_homeserver_whitelist(homeserver_whitelist):
    """Sets the homeserver whitelist

    Args:
        homeserver_whitelist (Iterable[str]): regex of whitelisted homeservers
    """
    global _homeserver_whitelist
    if homeserver_whitelist:
        # Makes a single regex which accepts all passed in regexes in the list
        _homeserver_whitelist = re.compile(
            "({})".format(")|(".join(homeserver_whitelist))
        )


@only_if_tracing
def whitelisted_homeserver(destination):
    """Checks if a destination matches the whitelist

    Args:
        destination (str)
        """
    global _homeserver_whitelist
    if _homeserver_whitelist:
        return _homeserver_whitelist.match(destination)
    return False


# Start spans and scopes

# Could use kwargs but I want these to be explicit
def start_active_span(
    operation_name,
    child_of=None,
    references=None,
    tags=None,
    start_time=None,
    ignore_active_span=False,
    finish_on_close=True,
):
    """Starts an active opentracing span. Note, the scope doesn't become active
    until it has been entered, however, the span starts from the time this
    message is called.
    Args:
        See opentracing.tracer
    Returns:
        scope (Scope) or noop_context_manager
    """

    if opentracing is None:
        return _noop_context_manager()

    else:
        # We need to enter the scope here for the logcontext to become active
        return opentracing.tracer.start_active_span(
            operation_name,
            child_of=child_of,
            references=references,
            tags=tags,
            start_time=start_time,
            ignore_active_span=ignore_active_span,
            finish_on_close=finish_on_close,
        )


def start_active_span_follows_from(operation_name, contexts):
    if opentracing is None:
        return _noop_context_manager()
    else:
        references = [opentracing.follows_from(context) for context in contexts]
        scope = start_active_span(operation_name, references=references)
        return scope


def start_active_span_from_context(
    headers,
    operation_name,
    references=None,
    tags=None,
    start_time=None,
    ignore_active_span=False,
    finish_on_close=True,
):
    """
    Extracts a span context from Twisted Headers.
    args:
        headers (twisted.web.http_headers.Headers)

        For the other args see opentracing.tracer

    returns:
        span_context (opentracing.span.SpanContext)
    """
    # Twisted encodes the values as lists whereas opentracing doesn't.
    # So, we take the first item in the list.
    # Also, twisted uses byte arrays while opentracing expects strings.

    if opentracing is None:
        return _noop_context_manager()

    header_dict = {k.decode(): v[0].decode() for k, v in headers.getAllRawHeaders()}
    context = opentracing.tracer.extract(opentracing.Format.HTTP_HEADERS, header_dict)

    return opentracing.tracer.start_active_span(
        operation_name,
        child_of=context,
        references=references,
        tags=tags,
        start_time=start_time,
        ignore_active_span=ignore_active_span,
        finish_on_close=finish_on_close,
    )


def start_active_span_from_edu(
    edu_content,
    operation_name,
    references=[],
    tags=None,
    start_time=None,
    ignore_active_span=False,
    finish_on_close=True,
):
    """
    Extracts a span context from an edu and uses it to start a new active span

    Args:
        edu_content (dict): and edu_content with a `context` field whose value is
        canonical json for a dict which contains opentracing information.

        For the other args see opentracing.tracer
    """

    if opentracing is None:
        return _noop_context_manager()

    carrier = json.loads(edu_content.get("context", "{}")).get("opentracing", {})
    context = opentracing.tracer.extract(opentracing.Format.TEXT_MAP, carrier)
    _references = [
        opentracing.child_of(span_context_from_string(x))
        for x in carrier.get("references", [])
    ]

    # For some reason jaeger decided not to support the visualization of multiple parent
    # spans or explicitely show references. I include the span context as a tag here as
    # an aid to people debugging but it's really not an ideal solution.

    references += _references

    scope = opentracing.tracer.start_active_span(
        operation_name,
        child_of=context,
        references=references,
        tags=tags,
        start_time=start_time,
        ignore_active_span=ignore_active_span,
        finish_on_close=finish_on_close,
    )

    scope.span.set_tag("references", carrier.get("references", []))
    return scope


# Opentracing setters for tags, logs, etc


@only_if_tracing
def set_tag(key, value):
    """Sets a tag on the active span"""
    opentracing.tracer.active_span.set_tag(key, value)


@only_if_tracing
def log_kv(key_values, timestamp=None):
    """Log to the active span"""
    opentracing.tracer.active_span.log_kv(key_values, timestamp)


@only_if_tracing
def set_operation_name(operation_name):
    """Sets the operation name of the active span"""
    opentracing.tracer.active_span.set_operation_name(operation_name)


# Injection and extraction


@only_if_tracing
def inject_active_span_twisted_headers(headers, destination):
    """
    Injects a span context into twisted headers in-place

    Args:
        headers (twisted.web.http_headers.Headers)
        span (opentracing.Span)

    Returns:
        In-place modification of headers

    Note:
        The headers set by the tracer are custom to the tracer implementation which
        should be unique enough that they don't interfere with any headers set by
        synapse or twisted. If we're still using jaeger these headers would be those
        here:
        https://github.com/jaegertracing/jaeger-client-python/blob/master/jaeger_client/constants.py
    """

    if not whitelisted_homeserver(destination):
        return

    span = opentracing.tracer.active_span
    carrier = {}
    opentracing.tracer.inject(span, opentracing.Format.HTTP_HEADERS, carrier)

    for key, value in carrier.items():
        headers.addRawHeaders(key, value)


@only_if_tracing
def inject_active_span_byte_dict(headers, destination):
    """
    Injects a span context into a dict where the headers are encoded as byte
    strings

    Args:
        headers (dict)
        span (opentracing.Span)

    Returns:
        In-place modification of headers

    Note:
        The headers set by the tracer are custom to the tracer implementation which
        should be unique enough that they don't interfere with any headers set by
        synapse or twisted. If we're still using jaeger these headers would be those
        here:
        https://github.com/jaegertracing/jaeger-client-python/blob/master/jaeger_client/constants.py
    """
    if not whitelisted_homeserver(destination):
        return

    span = opentracing.tracer.active_span

    carrier = {}
    opentracing.tracer.inject(span, opentracing.Format.HTTP_HEADERS, carrier)

    for key, value in carrier.items():
        headers[key.encode()] = [value.encode()]


@only_if_tracing
def inject_active_span_text_map(carrier, destination=None):
    """
    Injects a span context into a dict

    Args:
        carrier (dict)
        destination (str): the name of the remote server. The span context
        will only be injected if the destination matches the homeserver_whitelist
        or destination is None.

    Returns:
        In-place modification of carrier

    Note:
        The headers set by the tracer are custom to the tracer implementation which
        should be unique enough that they don't interfere with any headers set by
        synapse or twisted. If we're still using jaeger these headers would be those
        here:
        https://github.com/jaegertracing/jaeger-client-python/blob/master/jaeger_client/constants.py
    """

    if destination and not whitelisted_homeserver(destination):
        return

    opentracing.tracer.inject(
        opentracing.tracer.active_span, opentracing.Format.TEXT_MAP, carrier
    )


def active_span_context_as_string():
    """
    Returns:
        The active span context encoded as a string.
    """
    carrier = {}
    if opentracing:
        opentracing.tracer.inject(
            opentracing.tracer.active_span, opentracing.Format.TEXT_MAP, carrier
        )
    return json.dumps(carrier)


@only_if_tracing
def span_context_from_string(carrier):
    """
    Returns:
        The active span context decoded from a string.
    """
    carrier = json.loads(carrier)
    return opentracing.tracer.extract(opentracing.Format.TEXT_MAP, carrier)


@only_if_tracing
def extract_text_map(carrier):
    """
    Wrapper method for opentracing's tracer.extract for TEXT_MAP.
    Args:
        carrier (dict): a dict possibly containing a span context.

    Returns:
        The active span context extracted from carrier.
    """
    return opentracing.tracer.extract(opentracing.Format.TEXT_MAP, carrier)


# Tracing decorators


def trace_deferred(func):
    """Decorator to trace a deferred function. Sets the operation name to that of the
    function's."""

    if not opentracing:
        return func

    @wraps(func)
    @defer.inlineCallbacks
    def _trace_deferred_inner(self, *args, **kwargs):
        with start_active_span(func.__name__):
            r = yield func(self, *args, **kwargs)
            defer.returnValue(r)

    return _trace_deferred_inner


def trace_deferred_using_operation_name(name):
    """Decorator to trace a deferred function. Explicitely sets the operation_name."""

    def trace_deferred(func):

        if not opentracing:
            return func

        @wraps(func)
        @defer.inlineCallbacks
        def _trace_deferred_inner(self, *args, **kwargs):
            # Start scope
            with start_active_span(name):
                r = yield func(self, *args, **kwargs)
                defer.returnValue(r)

        return _trace_deferred_inner

    return trace_deferred


def trace(func):
    """Decorator to trace a normal function. Sets the operation name to that of the
    function's."""

    if not opentracing:
        return func

    @wraps(func)
    def _trace_inner(self, *args, **kwargs):
        with start_active_span(func.__name__):
            return func(self, *args, **kwargs)

    return _trace_inner


def trace_using_operation_name(operation_name):
    """Decorator to trace a function. Explicitely sets the operation_name."""

    def trace(func):

        if not opentracing:
            return func

        @wraps(func)
        def _trace_inner(self, *args, **kwargs):
            with start_active_span(operation_name):
                return func(self, *args, **kwargs)

        return _trace_inner

    return trace


def tag_args(func):
    """
    Tags all of the args to the active span.
    """

    if not opentracing:
        return func

    @wraps(func)
    def _tag_args_inner(self, *args, **kwargs):
        argspec = inspect.getargspec(func)
        for i, arg in enumerate(argspec.args[1:]):
            set_tag("ARG_" + arg, args[i])
        set_tag("args", args[len(argspec.args) :])
        set_tag("kwargs", kwargs)
        return func(self, *args, **kwargs)

    return _tag_args_inner


def trace_servlet(servlet_name, func):
    """Decorator which traces a serlet. It starts a span with some servlet specific
    tags such as the servlet_name and request information"""
    if not opentracing:
        return func

    @wraps(func)
    @defer.inlineCallbacks
    def _trace_servlet_inner(request, *args, **kwargs):
        with start_active_span_from_context(
            request.requestHeaders,
            "incoming-client-request",
            tags={
                "request_id": request.get_request_id(),
                tags.SPAN_KIND: tags.SPAN_KIND_RPC_SERVER,
                tags.HTTP_METHOD: request.get_method(),
                tags.HTTP_URL: request.get_redacted_uri(),
                tags.PEER_HOST_IPV6: request.getClientIP(),
                "servlet_name": servlet_name,
            },
        ):
            result = yield defer.maybeDeferred(func, request, *args, **kwargs)
            defer.returnValue(result)

    return _trace_servlet_inner


# Helper class


class _DummyTagNames(object):
    """wrapper of opentracings tags. We need to have them if we
    want to reference them without opentracing around. Clearly they
    should never actually show up in a trace. `set_tags` overwrites
    these with the correct ones."""

    INVALID_TAG = "invalid-tag"
    COMPONENT = INVALID_TAG
    DATABASE_INSTANCE = INVALID_TAG
    DATABASE_STATEMENT = INVALID_TAG
    DATABASE_TYPE = INVALID_TAG
    DATABASE_USER = INVALID_TAG
    ERROR = INVALID_TAG
    HTTP_METHOD = INVALID_TAG
    HTTP_STATUS_CODE = INVALID_TAG
    HTTP_URL = INVALID_TAG
    MESSAGE_BUS_DESTINATION = INVALID_TAG
    PEER_ADDRESS = INVALID_TAG
    PEER_HOSTNAME = INVALID_TAG
    PEER_HOST_IPV4 = INVALID_TAG
    PEER_HOST_IPV6 = INVALID_TAG
    PEER_PORT = INVALID_TAG
    PEER_SERVICE = INVALID_TAG
    SAMPLING_PRIORITY = INVALID_TAG
    SERVICE = INVALID_TAG
    SPAN_KIND = INVALID_TAG
    SPAN_KIND_CONSUMER = INVALID_TAG
    SPAN_KIND_PRODUCER = INVALID_TAG
    SPAN_KIND_RPC_CLIENT = INVALID_TAG
    SPAN_KIND_RPC_SERVER = INVALID_TAG


tags = _DummyTagNames
