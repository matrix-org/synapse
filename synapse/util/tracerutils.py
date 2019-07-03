# -*- coding: utf-8 -*-
# Copyright 2019 The Matrix.org Foundation C.I.C.d
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

try:
    import opentracing
except ImportError:
    opentracing = None

import logging
import re
from functools import wraps

logger = logging.getLogger(__name__)


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
    def f(*args, **kwargs):
        if opentracing:
            return func(*args, **kwargs)
        else:
            return

    return f


# Block everything by default
_homeserver_whitelist = None

tags = _DumTagNames


def init_tracer(config):
    """Set the whitelists and initialise the JaegerClient tracer

    Args:
        config (Config)
        The config used by the homserver. Here it's used to set the service
        name to the homeserver's.
    """
    if not config.tracer_config.get("tracer_enabled", False):
        # We don't have a tracer
        return

    if not opentracing:
        logger.error(
            "The server has been configure to use opentracing but "
            "the %s module has not been installed.", e.name
        )
        raise ModuleNotFoundError("opentracing")

    setup_tags()
    setup_tracing(config)


def setup_tracing(config):
    try:
        from jaeger_client import Config as JaegerConfig
        from synapse.util.scopecontextmanager import LogContextScopeManager
    except ImportError as e:
        logger.error(
            "The server has been configure to use opentracing but "
            "the %s module has not been installed.", e.name
        )
        raise

    # Include the worker name
    name = config.worker_name if config.worker_name else "master"

    set_homeserver_whitelist(config.tracer_config["homeserver_whitelist"])
    jaeger_config = JaegerConfig(
        config={"sampler": {"type": "const", "param": 1}, "logging": True},
        service_name="{} {}".format(config.server_name, name),
        scope_manager=LogContextScopeManager(config),
    )
    jaeger_config.initialize_tracer()


@only_if_tracing
def setup_tags():
    global tags
    tags = opentracing.tags


# Could use kwargs but I want these to be explicit
@only_if_tracing
def start_active_span(
    operation_name,
    child_of=None,
    references=None,
    tags=None,
    start_time=None,
    ignore_active_span=False,
    finish_on_close=True,
):
    # We need to enter the scope here for the logcontext to become active
    opentracing.tracer.start_active_span(
        operation_name,
        child_of=child_of,
        references=references,
        tags=tags,
        start_time=start_time,
        ignore_active_span=ignore_active_span,
        finish_on_close=finish_on_close,
    ).__enter__()


@only_if_tracing
def close_active_span():
    opentracing.tracer.scope_manager.active.__exit__(None, None, None)


@only_if_tracing
def set_tag(key, value):
    opentracing.tracer.active_span.set_tag(key, value)


@only_if_tracing
def log_kv(key_values, timestamp=None):
    opentracing.tracer.active_span.log_kv(key_values, timestamp)


# Note: we don't have a get baggage items because we're trying to hide all
# scope and span state from synapse. I think this method may also be useless
# as a result
@only_if_tracing
def set_baggage_item(key, value):
    opentracing.tracer.active_span.set_baggage_item(key, value)


@only_if_tracing
def set_operation_name(operation_name):
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
    global _homeserver_whitelist
    if _homeserver_whitelist:
        return _homeserver_whitelist.match(destination)
    return False


@only_if_tracing
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
    header_dict = {k.decode(): v[0].decode() for k, v in headers.getAllRawHeaders()}
    context = opentracing.tracer.extract(opentracing.Format.HTTP_HEADERS, header_dict)

    opentracing.tracer.start_active_span(
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
