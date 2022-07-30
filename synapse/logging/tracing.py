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
Most methods provided in the module have a direct correlation to those provided
by opentracing. Refer to docs there for a more in-depth documentation on some of
the args and methods.

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

At anytime where there is an active span ``opentracing.set_attribute`` can be used to
set a tag on the current active span.

Tracing functions
-----------------

Functions can be easily traced using decorators. The name of
the function becomes the operation name for the span.

.. code-block:: python

   from synapse.logging.opentracing import trace

   # Start a span using 'interesting_function' as the operation name
   @trace
   def interesting_function(*args, **kwargs):
       # Does all kinds of cool and expected things
       return something_usual_and_useful


Operation names can be explicitly set for a function by using ``trace_with_opname``:

.. code-block:: python

   from synapse.logging.opentracing import trace_with_opname

   @trace_with_opname("a_better_operation_name")
   def interesting_badly_named_function(*args, **kwargs):
       # Does all kinds of cool and expected things
       return something_usual_and_useful

Setting Tags
------------

To set a tag on the active span do

.. code-block:: python

   from synapse.logging.opentracing import set_attribute

   set_attribute(tag_name, tag_value)

There's a convenient decorator to tag all the args of the method. It uses
inspection in order to use the formal parameter names prefixed with 'ARG_' as
tag names. It uses kwarg names as tag names without the prefix.

.. code-block:: python

   from synapse.logging.opentracing import tag_args

   @tag_args
   def set_fates(clotho, lachesis, atropos, father="Zues", mother="Themis"):
       pass

   set_fates("the story", "the end", "the act")
   # This will have the following tags
   #  - ARG_clotho: "the story"
   #  - ARG_lachesis: "the end"
   #  - ARG_atropos: "the act"
   #  - father: "Zues"
   #  - mother: "Themis"

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

Most injection methods take a 'destination' arg. The context will only be injected
if the destination matches the whitelist or the destination is None.

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
import enum
import inspect
import logging
import re
from abc import ABC
from functools import wraps
from typing import (
    TYPE_CHECKING,
    Any,
    Callable,
    ContextManager,
    Dict,
    Generator,
    Iterable,
    Iterator,
    List,
    Optional,
    Pattern,
    Sequence,
    TypeVar,
    Union,
    cast,
    overload,
)

from typing_extensions import ParamSpec

from twisted.internet import defer
from twisted.web.http import Request
from twisted.web.http_headers import Headers

from synapse.config import ConfigError

if TYPE_CHECKING:
    from synapse.http.site import SynapseRequest
    from synapse.server import HomeServer

# Helper class


class _DummyLookup(object):
    """This will always returns the fixed value given for any accessed property"""

    def __init__(self, value):
        self.value = value

    def __getattribute__(self, name):
        return object.__getattribute__(self, "value")


class DummyLink(ABC):
    """Dummy placeholder for `opentelemetry.trace.Link`"""

    def __init__(self):
        self.not_implemented_message = (
            "opentelemetry wasn't imported so this is just a dummy link placeholder"
        )

    @property
    def context(self):
        raise NotImplementedError(self.not_implemented_message)

    @property
    def attributes(self):
        raise NotImplementedError(self.not_implemented_message)


# These dependencies are optional so they can fail to import
# and we
try:
    import opentelemetry
    import opentelemetry.exporter.jaeger.thrift
    import opentelemetry.propagate
    import opentelemetry.sdk.resources
    import opentelemetry.sdk.trace
    import opentelemetry.sdk.trace.export
    import opentelemetry.semconv.trace
    import opentelemetry.trace
    import opentelemetry.trace.propagation

    SpanKind = opentelemetry.trace.SpanKind
    SpanAttributes = opentelemetry.semconv.trace.SpanAttributes
    StatusCode = opentelemetry.trace.StatusCode
    Link = opentelemetry.trace.Link
except ImportError:
    opentelemetry = None  # type: ignore[assignment]
    SpanKind = _DummyLookup(0)
    SpanAttributes = _DummyLookup("fake-attribute")
    StatusCode = _DummyLookup(0)
    Link = DummyLink


logger = logging.getLogger(__name__)


class SynapseTags:
    """FIXME: Rename to `SynapseAttributes` so it matches OpenTelemetry `SpanAttributes`"""

    # The message ID of any to_device message processed
    TO_DEVICE_MESSAGE_ID = "to_device.message_id"

    # Whether the sync response has new data to be returned to the client.
    SYNC_RESULT = "sync.new_data"

    # incoming HTTP request ID  (as written in the logs)
    REQUEST_ID = "request_id"

    # HTTP request tag (used to distinguish full vs incremental syncs, etc)
    REQUEST_TAG = "request_tag"

    # Text description of a database transaction
    DB_TXN_DESC = "db.txn_desc"

    # Uniqueish ID of a database transaction
    DB_TXN_ID = "db.txn_id"

    # The name of the external cache
    CACHE_NAME = "cache.name"


class SynapseBaggage:
    FORCE_TRACING = "synapse-force-tracing"


# Block everything by default
# A regex which matches the server_names to expose traces for.
# None means 'block everything'.
_homeserver_whitelist: Optional[Pattern[str]] = None

# Util methods


class _Sentinel(enum.Enum):
    # defining a sentinel in this way allows mypy to correctly handle the
    # type of a dictionary lookup.
    sentinel = object()


P = ParamSpec("P")
R = TypeVar("R")
T = TypeVar("T")


def only_if_tracing(func: Callable[P, R]) -> Callable[P, Optional[R]]:
    """Executes the function only if we're tracing. Otherwise returns None."""

    @wraps(func)
    def _only_if_tracing_inner(*args: P.args, **kwargs: P.kwargs) -> Optional[R]:
        if opentelemetry:
            return func(*args, **kwargs)
        else:
            return None

    return _only_if_tracing_inner


@overload
def ensure_active_span(
    message: str,
) -> Callable[[Callable[P, R]], Callable[P, Optional[R]]]:
    ...


@overload
def ensure_active_span(
    message: str, ret: T
) -> Callable[[Callable[P, R]], Callable[P, Union[T, R]]]:
    ...


def ensure_active_span(
    message: str, ret: Optional[T] = None
) -> Callable[[Callable[P, R]], Callable[P, Union[Optional[T], R]]]:
    """Executes the operation only if opentelemetry is enabled and there is an active span.
    If there is no active span it logs message at the error level.

    Args:
        message: Message which fills in "There was no active span when trying to %s"
            in the error log if there is no active span and opentelemetry is enabled.
        ret: return value if opentelemetry is None or there is no active span.

    Returns:
        The result of the func, falling back to ret if opentelemetry is disabled or there
        was no active span.
    """

    def ensure_active_span_inner_1(
        func: Callable[P, R]
    ) -> Callable[P, Union[Optional[T], R]]:
        @wraps(func)
        def ensure_active_span_inner_2(
            *args: P.args, **kwargs: P.kwargs
        ) -> Union[Optional[T], R]:
            if not opentelemetry:
                return ret

            if not opentelemetry.trace.get_current_span():
                logger.error(
                    "There was no active span when trying to %s."
                    " Did you forget to start one or did a context slip?",
                    message,
                    stack_info=True,
                )

                return ret

            return func(*args, **kwargs)

        return ensure_active_span_inner_2

    return ensure_active_span_inner_1


# Setup


def init_tracer(hs: "HomeServer") -> None:
    """Set the whitelists and initialise the OpenTelemetry tracer"""
    global opentelemetry
    if not hs.config.tracing.opentelemetry_enabled:
        # We don't have a tracer
        opentelemetry = None  # type: ignore[assignment]
        return

    if not opentelemetry:
        raise ConfigError(
            "The server has been configured to use OpenTelemetry but OpenTelemetry is not "
            "installed."
        )

    # Pull out of the config if it was given. Otherwise set it to something sensible.
    set_homeserver_whitelist(hs.config.tracing.opentelemetry_whitelist)

    resource = opentelemetry.sdk.resources.Resource(
        attributes={
            opentelemetry.sdk.resources.SERVICE_NAME: f"{hs.config.server.server_name} {hs.get_instance_name()}"
        }
    )

    provider = opentelemetry.sdk.trace.TracerProvider(resource=resource)

    # consoleProcessor = opentelemetry.sdk.trace.export.BatchSpanProcessor(
    #     opentelemetry.sdk.trace.export.ConsoleSpanExporter()
    # )
    # provider.add_span_processor(consoleProcessor)

    jaeger_exporter = opentelemetry.exporter.jaeger.thrift.JaegerExporter(
        **hs.config.tracing.jaeger_exporter_config
    )
    jaeger_processor = opentelemetry.sdk.trace.export.BatchSpanProcessor(
        jaeger_exporter
    )
    provider.add_span_processor(jaeger_processor)

    # Sets the global default tracer provider
    opentelemetry.trace.set_tracer_provider(provider)


# Whitelisting


@only_if_tracing
def set_homeserver_whitelist(homeserver_whitelist: Iterable[str]) -> None:
    """Sets the homeserver whitelist

    Args:
        homeserver_whitelist: regexes specifying whitelisted homeservers
    """
    global _homeserver_whitelist
    if homeserver_whitelist:
        # Makes a single regex which accepts all passed in regexes in the list
        _homeserver_whitelist = re.compile(
            "({})".format(")|(".join(homeserver_whitelist))
        )


@only_if_tracing
def whitelisted_homeserver(destination: str) -> bool:
    """Checks if a destination matches the whitelist

    Args:
        destination
    """

    if _homeserver_whitelist:
        return _homeserver_whitelist.match(destination) is not None
    return False


# Start spans and scopes


def create_non_recording_span():
    if opentelemetry is None:
        return contextlib.nullcontext()  # type: ignore[unreachable]

    return opentelemetry.trace.NonRecordingSpan(
        opentelemetry.trace.INVALID_SPAN_CONTEXT
    )


def start_active_span(
    name: str,
    *,
    context: Optional["opentelemetry.context.context.Context"] = None,
    kind: Optional["opentelemetry.trace.SpanKind"] = SpanKind.INTERNAL,
    attributes: "opentelemetry.util.types.Attributes" = None,
    links: Optional[Sequence["opentelemetry.trace.Link"]] = None,
    start_time: Optional[int] = None,
    record_exception: bool = True,
    set_status_on_exception: bool = True,
    end_on_exit: bool = True,
    # For testing only
    tracer: Optional["opentelemetry.sdk.trace.TracerProvider"] = None,
) -> ContextManager["opentelemetry.trace.span.Span"]:
    if opentelemetry is None:
        return contextlib.nullcontext()  # type: ignore[unreachable]

    if tracer is None:
        tracer = opentelemetry.trace.get_tracer(__name__)

    return tracer.start_as_current_span(
        name=name,
        context=context,
        kind=kind,
        attributes=attributes,
        links=links,
        start_time=start_time,
        record_exception=record_exception,
        set_status_on_exception=set_status_on_exception,
        end_on_exit=end_on_exit,
    )


def start_active_span_from_edu(
    edu_content: Dict[str, Any],
    operation_name: str,
) -> Iterator["opentelemetry.trace.span.Span"]:
    """
    Extracts a span context from an edu and uses it to start a new active span

    Args:
        edu_content: an edu_content with a `context` field whose value is
        canonical json for a dict which contains opentracing information.

        For the other args see opentracing.tracer
    """
    # TODO
    pass


# OpenTelemetry setters for attributes, logs, etc
@only_if_tracing
def get_active_span() -> Optional["opentelemetry.trace.span.Span"]:
    """Get the currently active span, if any"""
    return opentelemetry.trace.get_current_span()


@ensure_active_span("set a tag")
def set_attribute(key: str, value: Union[str, bool, int, float]) -> None:
    """Sets a tag on the active span"""
    active_span = get_active_span()
    assert active_span is not None
    active_span.set_attribute(key, value)


@ensure_active_span("set the status")
def set_status(
    status: "opentelemetry.trace.StatusCode", exc: Optional[Exception]
) -> None:
    """Sets a tag on the active span"""
    active_span = get_active_span()
    assert active_span is not None
    active_span.set_status(status)
    if exc:
        active_span.record_exception(exc)


DEFAULT_LOG_NAME = "log"


@ensure_active_span("log")
def log_kv(key_values: Dict[str, Any], timestamp: Optional[float] = None) -> None:
    """Log to the active span"""
    active_span = get_active_span()
    assert active_span is not None
    event_name = key_values.get("event", DEFAULT_LOG_NAME)
    active_span.add_event(event_name, attributes=key_values, timestamp=timestamp)


@only_if_tracing
def force_tracing(
    span: Union[
        "opentelemetry.shim.opentracing_shim.SpanShim", _Sentinel
    ] = _Sentinel.sentinel
) -> None:
    """Force sampling for the active/given span and its children.

    Args:
        span: span to force tracing for. By default, the active span.
    """
    # TODO
    pass


def is_context_forced_tracing(
    span_context: Optional["opentelemetry.shim.opentracing_shim.SpanContextShim"],
) -> bool:
    """Check if sampling has been force for the given span context."""
    # TODO
    return False


# Injection and extraction


@ensure_active_span("inject the span into a header dict")
def inject_active_span_context_into_header_dict(
    headers: Dict[bytes, List[bytes]],
    destination: Optional[str] = None,
    check_destination: bool = True,
) -> None:
    """
    Injects a span context into a dict of HTTP headers

    Args:
        headers: the dict to inject headers into
        destination: address of entity receiving the span context. Must be given unless
            `check_destination` is False.
        check_destination (bool): If False, destination will be ignored and the context
            will always be injected. If True, the context will only be injected if the
            destination matches the tracing allowlist

    Note:
        The headers set by the tracer are custom to the tracer implementation which
        should be unique enough that they don't interfere with any headers set by
        synapse or twisted. If we're still using jaeger these headers would be those
        here:
        https://github.com/jaegertracing/jaeger-client-python/blob/master/jaeger_client/constants.py
    """
    if check_destination:
        if destination is None:
            raise ValueError(
                "destination must be given unless check_destination is False"
            )
        if not whitelisted_homeserver(destination):
            return

    active_span = get_active_span()
    # This doesn't affect the current context at all, it just converts a span
    # into `Context` object basically (bad name).
    ctx = opentelemetry.trace.propagation.set_span_in_context(active_span)

    propagator = opentelemetry.propagate.get_global_textmap()
    # Put all of SpanContext properties into the headers dict
    propagator.inject(headers, context=ctx)


def inject_response_headers(response_headers: Headers) -> None:
    """Inject the current trace id into the HTTP response headers"""
    if not opentelemetry:
        return
    active_span = get_active_span()
    if not active_span:
        return

    trace_id = active_span.get_span_context().trace_id

    if trace_id is not None:
        response_headers.addRawHeader("Synapse-Trace-Id", f"{trace_id:x}")


@ensure_active_span(
    "get the active span context as a dict", ret=cast(Dict[str, str], {})
)
def get_active_span_text_map(destination: Optional[str] = None) -> Dict[str, str]:
    """
    Gets a span context as a dict. This can be used instead of manually
    injecting a span into an empty carrier.

    Args:
        destination: the name of the remote server.

    Returns:
        dict: the active span's context if opentracing is enabled, otherwise empty.
    """
    if destination and not whitelisted_homeserver(destination):
        return {}

    active_span = get_active_span()
    # This doesn't affect the current context at all, it just converts a span
    # into `Context` object basically (bad name).
    ctx = opentelemetry.trace.propagation.set_span_in_context(active_span)

    carrier_text_map: Dict[str, str] = {}
    propagator = opentelemetry.propagate.get_global_textmap()
    # Put all of SpanContext properties onto the carrier text map that we can return
    propagator.inject(carrier_text_map, context=ctx)

    return carrier_text_map


def span_context_from_request(
    request: Request,
) -> Optional["opentelemetry.trace.span.SpanContext"]:
    """Extract an opentracing context from the headers on an HTTP request

    This is useful when we have received an HTTP request from another part of our
    system, and want to link our spans to those of the remote system.
    """
    if not opentelemetry:
        return None
    header_dict = {
        k.decode(): v[0].decode() for k, v in request.requestHeaders.getAllRawHeaders()
    }

    # Extract all of the relevant values from the headers to construct a
    # SpanContext to return.
    return extract_text_map(header_dict)


@only_if_tracing
def extract_text_map(
    carrier: Dict[str, str]
) -> Optional["opentelemetry.shim.opentracing_shim.SpanContextShim"]:
    """
    Wrapper method for opentracing's tracer.extract for TEXT_MAP.
    Args:
        carrier: a dict possibly containing a span context.

    Returns:
        The active span context extracted from carrier.
    """
    propagator = opentelemetry.propagate.get_global_textmap()
    # Extract all of the relevant values from the `carrier` to construct a
    # SpanContext to return.
    return propagator.extract(carrier)


# Tracing decorators


def trace_with_opname(opname: str) -> Callable[[Callable[P, R]], Callable[P, R]]:
    """
    Decorator to trace a function with a custom opname.

    See the module's doc string for usage examples.

    """

    def decorator(func: Callable[P, R]) -> Callable[P, R]:
        if opentelemetry is None:
            return func  # type: ignore[unreachable]

        if inspect.iscoroutinefunction(func):

            @wraps(func)
            async def _trace_inner(*args: P.args, **kwargs: P.kwargs) -> R:
                with start_active_span(opname):
                    return await func(*args, **kwargs)  # type: ignore[misc]

        else:
            # The other case here handles both sync functions and those
            # decorated with inlineDeferred.
            @wraps(func)
            def _trace_inner(*args: P.args, **kwargs: P.kwargs) -> R:
                scope = start_active_span(opname)
                scope.__enter__()

                try:
                    result = func(*args, **kwargs)
                    if isinstance(result, defer.Deferred):

                        def call_back(result: R) -> R:
                            scope.__exit__(None, None, None)
                            return result

                        def err_back(result: R) -> R:
                            scope.__exit__(None, None, None)
                            return result

                        result.addCallbacks(call_back, err_back)

                    else:
                        if inspect.isawaitable(result):
                            logger.error(
                                "@trace may not have wrapped %s correctly! "
                                "The function is not async but returned a %s.",
                                func.__qualname__,
                                type(result).__name__,
                            )

                        scope.__exit__(None, None, None)

                    return result

                except Exception as e:
                    scope.__exit__(type(e), None, e.__traceback__)
                    raise

        return _trace_inner  # type: ignore[return-value]

    return decorator


def trace(func: Callable[P, R]) -> Callable[P, R]:
    """
    Decorator to trace a function.

    Sets the operation name to that of the function's name.

    See the module's doc string for usage examples.
    """

    return trace_with_opname(func.__name__)(func)


def tag_args(func: Callable[P, R]) -> Callable[P, R]:
    """
    Tags all of the args to the active span.
    """

    if not opentelemetry:
        return func

    @wraps(func)
    def _tag_args_inner(*args: P.args, **kwargs: P.kwargs) -> R:
        argspec = inspect.getfullargspec(func)
        for i, arg in enumerate(argspec.args[1:]):
            set_attribute("ARG_" + arg, args[i])  # type: ignore[index]
        set_attribute("args", args[len(argspec.args) :])  # type: ignore[index]
        set_attribute("kwargs", str(kwargs))
        return func(*args, **kwargs)

    return _tag_args_inner


@contextlib.contextmanager
def trace_servlet(
    request: "SynapseRequest", extract_context: bool = False
) -> Generator[None, None, None]:
    """Returns a context manager which traces a request. It starts a span
    with some servlet specific tags such as the request metrics name and
    request information.

    Args:
        request
        extract_context: Whether to attempt to extract the opentracing
            context from the request the servlet is handling.
    """

    if opentelemetry is None:
        yield  # type: ignore[unreachable]
        return

    request_attrs = {
        SynapseTags.REQUEST_ID: request.get_request_id(),
        SpanAttributes.HTTP_METHOD: request.get_method(),
        SpanAttributes.HTTP_URL: request.get_redacted_uri(),
        # TODO: Is this the correct attribute to use for this?
        SpanAttributes.NET_PEER_IP: request.getClientAddress().host,
    }

    request_name = request.request_metrics.name
    span_context = span_context_from_request(request) if extract_context else None

    # we configure the scope not to finish the span immediately on exit, and instead
    # pass the span into the SynapseRequest, which will finish it once we've finished
    # sending the response to the client.

    with start_active_span(
        request_name,
        kind=SpanKind.SERVER,
        context=span_context,
        end_on_exit=False,
    ) as span:
        request.set_tracing_span(span)

        inject_response_headers(request.responseHeaders)
        try:
            yield
        finally:
            # We set the operation name again in case its changed (which happens
            # with JsonResource).
            span.update_name(request.request_metrics.name)

            # set the tags *after* the servlet completes, in case it decided to
            # prioritise the span (tags will get dropped on unprioritised spans)
            request_attrs[
                SynapseTags.REQUEST_TAG
            ] = request.request_metrics.start_context.tag

            for k, v in request_attrs.items():
                span.set_attribute(k, v)
