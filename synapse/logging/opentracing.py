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

"""
============================
Using OpenTracing in Synapse
============================

Python-specific tracing concepts are at https://opentracing.io/guides/python/.
Note that Synapse wraps OpenTracing in a small module (this one) in order to make the
OpenTracing dependency optional. That means that the access patterns are
different to those demonstrated in the OpenTracing guides. However, it is
still useful to know, especially if OpenTracing is included as a full dependency
in the future or if you are modifying this module.


OpenTracing is encapsulated so that
no span objects from OpenTracing are exposed in Synapse's code. This allows
OpenTracing to be easily disabled in Synapse and thereby have OpenTracing as
an optional dependency. This does however limit the number of modifiable spans
at any point in the code to one. From here out references to `opentracing`
in the code snippets refer to the Synapses module.

Tracing
-------

In Synapse it is not possible to start a non-active span. Spans can be started
using the ``start_active_span`` method. This returns a scope (see
OpenTracing docs) which is a context manager that needs to be entered and
exited. This is usually done by using ``with``.

.. code-block:: python

   from synapse.logging.opentracing import start_active_span

   with start_active_span("operation name"):
       # Do something we want to tracer

Forgetting to enter or exit a scope will result in some mysterious and grievous log
context errors.

At anytime where there is an active span ``opentracing.set_tag`` can be used to
set a tag on the current active span.

Tracing functions
-----------------

Functions can be easily traced using decorators. There is a decorator for
'normal' function and for functions which are actually deferreds. The name of
the function becomes the operation name for the span.

.. code-block:: python

   from synapse.logging.opentracing import trace, trace_deferred

   # Start a span using 'normal_function' as the operation name
   @trace
   def normal_function(*args, **kwargs):
       # Does all kinds of cool and expected things
       return something_usual_and_useful

   # Start a span using 'deferred_function' as the operation name
   @trace_deferred
   @defer.inlineCallbacks
   def deferred_function(*args, **kwargs):
       # We start
       yield we_wait
       # we finish
       defer.returnValue(something_usual_and_useful)

Operation names can be explicitly set for functions by using
``trace_using_operation_name`` and
``trace_deferred_using_operation_name``

.. code-block:: python

   from synapse.logging.opentracing import (
       trace_using_operation_name,
       trace_deferred_using_operation_name
   )

   @trace_using_operation_name("A *much* better operation name")
   def normal_function(*args, **kwargs):
       # Does all kinds of cool and expected things
       return something_usual_and_useful

   @trace_deferred_using_operation_name("Another exciting operation name!")
   @defer.inlineCallbacks
   def deferred_function(*args, **kwargs):
       # We start
       yield we_wait
       # we finish
       defer.returnValue(something_usual_and_useful)

Contexts and carriers
---------------------

There are a selection of wrappers for injecting and extracting contexts from
carriers provided. Unfortunately OpenTracing's three context injection
techniques are not adequate for our inject of OpenTracing span-contexts into
Twisted's http headers, EDU contents and our database tables. Also note that
the binary encoding format mandated by OpenTracing is not actually implemented
by jaeger_client v4.0.0 - it will silently noop.
Please refer to the end of ``logging/opentracing.py`` for the available
injection and extraction methods.

Homeserver whitelisting
-----------------------

Most of the whitelist checks are encapsulated in the modules's injection
and extraction method but be aware that using custom carriers or crossing
unchartered waters will require the enforcement of the whitelist.
``logging/opentracing.py`` has a ``whitelisted_homeserver`` method which takes
in a destination and compares it to the whitelist.

=======
Gotchas
=======

- Checking whitelists on span propagation
- Inserting pii
- Forgetting to enter or exit a scope
- Span source: make sure that the span you expect to be active across a
  function call really will be that one. Does the current function have more
  than one caller? Will all of those calling functions have be in a context
  with an active span?
"""

import contextlib
import logging
import re
from functools import wraps

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

    # Pull out the jaeger config if it was given. Otherwise set it to something sensible.
    # See https://github.com/jaegertracing/jaeger-client-python/blob/master/jaeger_client/config.py

    set_homeserver_whitelist(config.opentracer_whitelist)

    JaegerConfig(
        config=config.jaeger_config,
        service_name="{} {}".format(config.server_name, name),
        scope_manager=LogContextScopeManager(config),
    ).initialize_tracer()

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
        with start_active_span(
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
