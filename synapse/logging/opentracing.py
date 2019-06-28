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
# limitations under the License.import opentracing


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
import logging
import re
from functools import wraps
from twisted.internet import defer


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
import inspect


class _DumTagNames(object):
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


# A regex which matches the server_names to expose traces for.
# None means 'block everything'.
_homeserver_whitelist = None

tags = _DumTagNames


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


@contextlib.contextmanager
def _noop_context_manager(*args, **kwargs):
    """Does absolutely nothing really well. Can be entered and exited arbitrarily.
    Good substitute for an opentracing scope."""
    yield


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


@only_if_tracing
def close_active_span():
    """Closes the active span. This will close it's logcontext if the context
    was made for the span"""
    opentracing.tracer.scope_manager.active.__exit__(None, None, None)


@only_if_tracing
def set_tag(key, value):
    """Set's a tag on the active span"""
    opentracing.tracer.active_span.set_tag(key, value)


@only_if_tracing
def log_kv(key_values, timestamp=None):
    """Log to the active span"""
    opentracing.tracer.active_span.log_kv(key_values, timestamp)


# Note: we don't have a get baggage items because we're trying to hide all
# scope and span state from synapse. I think this method may also be useless
# as a result
@only_if_tracing
def set_baggage_item(key, value):
    """Attach baggage to the active span"""
    opentracing.tracer.active_span.set_baggage_item(key, value)


@only_if_tracing
def set_operation_name(operation_name):
    """Sets the operation name of the active span"""
    opentracing.tracer.active_span.set_operation_name(operation_name)


@only_if_tracing
def set_homeserver_whitelist(homeserver_whitelist):
    """Sets the whitelist

    Args:
        homeserver_whitelist (iterable of strings): regex of whitelisted homeservers
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
        destination (String)"""
    if _homeserver_whitelist:
        return _homeserver_whitelist.match(destination)
    return False


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


@only_if_tracing
def inject_active_span_twisted_headers(headers, destination):
    """
    Injects a span context into twisted headers inplace

    Args:
        headers (twisted.web.http_headers.Headers)
        span (opentracing.Span)

    Returns:
        Inplace modification of headers

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
        Inplace modification of headers

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


def trace_servlet(servlet_name, func):
    """Decorator which traces a serlet. It starts a span with some servlet specific
    tags such as the servlet_name and request information"""

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


def trace_defered_function(func):
    @wraps(func)
    @defer.inlineCallbacks
    def f(self, *args, **kwargs):
        # Start scope
        TracerUtil.start_active_span(func.__name__)
        try:
            r = yield func(self, *args, **kwargs)
        except:
            raise
        finally:
            TracerUtil.close_active_span()
        defer.returnValue(r)

    return f


def trace_defered_function_using_operation_name(name):
    def trace_defered_function(func):
        @wraps(func)
        @defer.inlineCallbacks
        def f(self, *args, **kwargs):
            # Start scope
            TracerUtil.start_active_span(name)
            try:
                r = yield func(self, *args, **kwargs)
            except:
                raise
            finally:
                TracerUtil.close_active_span()
            defer.returnValue(r)

        return f

    return trace_defered_function


def trace_function(func):
    @wraps(func)
    def f(self, *args, **kwargs):
        TracerUtil.start_active_span(func.__name__)
        try:
            return func(self, *args, **kwargs)
        finally:
            TracerUtil.close_active_span()

    return f


def tag_args(func):
    @wraps(func)
    def f(self, *args, **kwargs):
        TracerUtil.set_tag("args", args)
        TracerUtil.set_tag("kwargs", kwargs)
        return func(self, *args, **kwargs)

    return f


def wrap_in_span(func):
    """Its purpose is to wrap a function that is being passed into a context
    which is a complete break from the current logcontext. This function creates
    a non active span from the current context and closes it after the function
    executes."""

    # I haven't use this function yet

    if not TracerUtil._opentracing:
        return func

    span = TracerUtil._opentracing.tracer.start_span(
        func.__name__, child_of=TracerUtil._opentracing.tracer.active_span
    )

    @wraps(func)
    def f(self, *args, **kwargs):
        try:
            return func(self, *args, **kwargs)
        except Exception as e:
            span.set_tag("error", True)
            span.log_kv({"exception", e})
            raise
        finally:
            span.finish()

    return f
