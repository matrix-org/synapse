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

At anytime where there is an active span ``opentracing.set_tag`` can be used to
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


Operation names can be explicitly set for a function by passing the
operation name to ``trace``

.. code-block:: python

   from synapse.logging.opentracing import trace

   @trace(opname="a_better_operation_name")
   def interesting_badly_named_function(*args, **kwargs):
       # Does all kinds of cool and expected things
       return something_usual_and_useful

Setting Tags
------------

To set a tag on the active span do

.. code-block:: python

   from synapse.logging.opentracing import set_tag

   set_tag(tag_name, tag_value)

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
from functools import wraps
from typing import (
    TYPE_CHECKING,
    Any,
    Callable,
    Collection,
    Dict,
    Generator,
    Iterable,
    List,
    Optional,
    Pattern,
    Type,
    TypeVar,
    Union,
)

import attr
from typing_extensions import ParamSpec

from twisted.internet import defer
from twisted.web.http import Request
from twisted.web.http_headers import Headers

from synapse.config import ConfigError
from synapse.util import json_decoder, json_encoder

if TYPE_CHECKING:
    from synapse.http.site import SynapseRequest
    from synapse.server import HomeServer

# Helper class


class _DummyTagNames:
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


try:
    import opentracing
    import opentracing.tags

    tags = opentracing.tags
except ImportError:
    opentracing = None  # type: ignore[assignment]
    tags = _DummyTagNames  # type: ignore[assignment]
try:
    from jaeger_client import Config as JaegerConfig

    from synapse.logging.scopecontextmanager import LogContextScopeManager
except ImportError:
    JaegerConfig = None  # type: ignore
    LogContextScopeManager = None  # type: ignore


try:
    from rust_python_jaeger_reporter import Reporter

    # jaeger-client 4.7.0 requires that reporters inherit from BaseReporter, which
    # didn't exist before that version.
    try:
        from jaeger_client.reporter import BaseReporter
    except ImportError:

        class BaseReporter:  # type: ignore[no-redef]
            pass

    @attr.s(slots=True, frozen=True, auto_attribs=True)
    class _WrappedRustReporter(BaseReporter):
        """Wrap the reporter to ensure `report_span` never throws."""

        _reporter: Reporter = attr.Factory(Reporter)

        def set_process(self, *args: Any, **kwargs: Any) -> None:
            return self._reporter.set_process(*args, **kwargs)

        def report_span(self, span: "opentracing.Span") -> None:
            try:
                return self._reporter.report_span(span)
            except Exception:
                logger.exception("Failed to report span")

    RustReporter: Optional[Type[_WrappedRustReporter]] = _WrappedRustReporter
except ImportError:
    RustReporter = None


logger = logging.getLogger(__name__)


class SynapseTags:
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


def only_if_tracing(func: Callable[P, R]) -> Callable[P, Optional[R]]:
    """Executes the function only if we're tracing. Otherwise returns None."""

    @wraps(func)
    def _only_if_tracing_inner(*args: P.args, **kwargs: P.kwargs) -> Optional[R]:
        if opentracing:
            return func(*args, **kwargs)
        else:
            return None

    return _only_if_tracing_inner


def ensure_active_span(message: str, ret=None):
    """Executes the operation only if opentracing is enabled and there is an active span.
    If there is no active span it logs message at the error level.

    Args:
        message: Message which fills in "There was no active span when trying to %s"
            in the error log if there is no active span and opentracing is enabled.
        ret (object): return value if opentracing is None or there is no active span.

    Returns (object): The result of the func or ret if opentracing is disabled or there
        was no active span.
    """

    def ensure_active_span_inner_1(func):
        @wraps(func)
        def ensure_active_span_inner_2(*args, **kwargs):
            if not opentracing:
                return ret

            if not opentracing.tracer.active_span:
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
    """Set the whitelists and initialise the JaegerClient tracer"""
    global opentracing
    if not hs.config.tracing.opentracer_enabled:
        # We don't have a tracer
        opentracing = None  # type: ignore[assignment]
        return

    if not opentracing or not JaegerConfig:
        raise ConfigError(
            "The server has been configured to use opentracing but opentracing is not "
            "installed."
        )

    # Pull out the jaeger config if it was given. Otherwise set it to something sensible.
    # See https://github.com/jaegertracing/jaeger-client-python/blob/master/jaeger_client/config.py

    set_homeserver_whitelist(hs.config.tracing.opentracer_whitelist)

    from jaeger_client.metrics.prometheus import PrometheusMetricsFactory

    config = JaegerConfig(
        config=hs.config.tracing.jaeger_config,
        service_name=f"{hs.config.server.server_name} {hs.get_instance_name()}",
        scope_manager=LogContextScopeManager(),
        metrics_factory=PrometheusMetricsFactory(),
    )

    # If we have the rust jaeger reporter available let's use that.
    if RustReporter:
        logger.info("Using rust_python_jaeger_reporter library")
        assert config.sampler is not None
        tracer = config.create_tracer(RustReporter(), config.sampler)
        opentracing.set_global_tracer(tracer)
    else:
        config.initialize_tracer()


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

# Could use kwargs but I want these to be explicit
def start_active_span(
    operation_name: str,
    child_of: Optional[Union["opentracing.Span", "opentracing.SpanContext"]] = None,
    references: Optional[List["opentracing.Reference"]] = None,
    tags: Optional[Dict[str, str]] = None,
    start_time: Optional[float] = None,
    ignore_active_span: bool = False,
    finish_on_close: bool = True,
    *,
    tracer: Optional["opentracing.Tracer"] = None,
):
    """Starts an active opentracing span.

    Records the start time for the span, and sets it as the "active span" in the
    scope manager.

    Args:
        See opentracing.tracer
    Returns:
        scope (Scope) or contextlib.nullcontext
    """

    if opentracing is None:
        return contextlib.nullcontext()  # type: ignore[unreachable]

    if tracer is None:
        # use the global tracer by default
        tracer = opentracing.tracer

    return tracer.start_active_span(
        operation_name,
        child_of=child_of,
        references=references,
        tags=tags,
        start_time=start_time,
        ignore_active_span=ignore_active_span,
        finish_on_close=finish_on_close,
    )


def start_active_span_follows_from(
    operation_name: str,
    contexts: Collection,
    child_of: Optional[Union["opentracing.Span", "opentracing.SpanContext"]] = None,
    start_time: Optional[float] = None,
    *,
    inherit_force_tracing: bool = False,
    tracer: Optional["opentracing.Tracer"] = None,
):
    """Starts an active opentracing span, with additional references to previous spans

    Args:
        operation_name: name of the operation represented by the new span
        contexts: the previous spans to inherit from

        child_of: optionally override the parent span. If unset, the currently active
           span will be the parent. (If there is no currently active span, the first
           span in `contexts` will be the parent.)

        start_time: optional override for the start time of the created span. Seconds
            since the epoch.

        inherit_force_tracing: if set, and any of the previous contexts have had tracing
           forced, the new span will also have tracing forced.
        tracer: override the opentracing tracer. By default the global tracer is used.
    """
    if opentracing is None:
        return contextlib.nullcontext()  # type: ignore[unreachable]

    references = [opentracing.follows_from(context) for context in contexts]
    scope = start_active_span(
        operation_name,
        child_of=child_of,
        references=references,
        start_time=start_time,
        tracer=tracer,
    )

    if inherit_force_tracing and any(
        is_context_forced_tracing(ctx) for ctx in contexts
    ):
        force_tracing(scope.span)

    return scope


def start_active_span_from_edu(
    edu_content: Dict[str, Any],
    operation_name: str,
    references: Optional[List["opentracing.Reference"]] = None,
    tags: Optional[Dict[str, str]] = None,
    start_time: Optional[float] = None,
    ignore_active_span: bool = False,
    finish_on_close: bool = True,
) -> "opentracing.Scope":
    """
    Extracts a span context from an edu and uses it to start a new active span

    Args:
        edu_content: an edu_content with a `context` field whose value is
        canonical json for a dict which contains opentracing information.

        For the other args see opentracing.tracer
    """
    references = references or []

    if opentracing is None:
        return contextlib.nullcontext()  # type: ignore[unreachable]

    carrier = json_decoder.decode(edu_content.get("context", "{}")).get(
        "opentracing", {}
    )
    context = opentracing.tracer.extract(opentracing.Format.TEXT_MAP, carrier)
    _references = [
        opentracing.child_of(span_context_from_string(x))
        for x in carrier.get("references", [])
    ]

    # For some reason jaeger decided not to support the visualization of multiple parent
    # spans or explicitly show references. I include the span context as a tag here as
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
def active_span() -> Optional["opentracing.Span"]:
    """Get the currently active span, if any"""
    return opentracing.tracer.active_span


@ensure_active_span("set a tag")
def set_tag(key: str, value: Union[str, bool, int, float]) -> None:
    """Sets a tag on the active span"""
    assert opentracing.tracer.active_span is not None
    opentracing.tracer.active_span.set_tag(key, value)


@ensure_active_span("log")
def log_kv(key_values: Dict[str, Any], timestamp: Optional[float] = None) -> None:
    """Log to the active span"""
    assert opentracing.tracer.active_span is not None
    opentracing.tracer.active_span.log_kv(key_values, timestamp)


@ensure_active_span("set the traces operation name")
def set_operation_name(operation_name: str) -> None:
    """Sets the operation name of the active span"""
    assert opentracing.tracer.active_span is not None
    opentracing.tracer.active_span.set_operation_name(operation_name)


@only_if_tracing
def force_tracing(
    span: Union["opentracing.Span", _Sentinel] = _Sentinel.sentinel
) -> None:
    """Force sampling for the active/given span and its children.

    Args:
        span: span to force tracing for. By default, the active span.
    """
    if isinstance(span, _Sentinel):
        span_to_trace = opentracing.tracer.active_span
    else:
        span_to_trace = span
    if span_to_trace is None:
        logger.error("No active span in force_tracing")
        return

    span_to_trace.set_tag(opentracing.tags.SAMPLING_PRIORITY, 1)

    # also set a bit of baggage, so that we have a way of figuring out if
    # it is enabled later
    span_to_trace.set_baggage_item(SynapseBaggage.FORCE_TRACING, "1")


def is_context_forced_tracing(
    span_context: Optional["opentracing.SpanContext"],
) -> bool:
    """Check if sampling has been force for the given span context."""
    if span_context is None:
        return False
    return span_context.baggage.get(SynapseBaggage.FORCE_TRACING) is not None


# Injection and extraction


@ensure_active_span("inject the span into a header dict")
def inject_header_dict(
    headers: Dict[bytes, List[bytes]],
    destination: Optional[str] = None,
    check_destination: bool = True,
) -> None:
    """
    Injects a span context into a dict of HTTP headers

    Args:
        headers: the dict to inject headers into
        destination: address of entity receiving the span context. Must be given unless
            check_destination is False. The context will only be injected if the
            destination matches the opentracing whitelist
        check_destination (bool): If false, destination will be ignored and the context
            will always be injected.

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

    span = opentracing.tracer.active_span

    carrier: Dict[str, str] = {}
    assert span is not None
    opentracing.tracer.inject(span.context, opentracing.Format.HTTP_HEADERS, carrier)

    for key, value in carrier.items():
        headers[key.encode()] = [value.encode()]


def inject_response_headers(response_headers: Headers) -> None:
    """Inject the current trace id into the HTTP response headers"""
    if not opentracing:
        return
    span = opentracing.tracer.active_span
    if not span:
        return

    # This is a bit implementation-specific.
    #
    # Jaeger's Spans have a trace_id property; other implementations (including the
    # dummy opentracing.span.Span which we use if init_tracer is not called) do not
    # expose it
    trace_id = getattr(span, "trace_id", None)

    if trace_id is not None:
        response_headers.addRawHeader("Synapse-Trace-Id", f"{trace_id:x}")


@ensure_active_span("get the active span context as a dict", ret={})
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

    carrier: Dict[str, str] = {}
    assert opentracing.tracer.active_span is not None
    opentracing.tracer.inject(
        opentracing.tracer.active_span.context, opentracing.Format.TEXT_MAP, carrier
    )

    return carrier


@ensure_active_span("get the span context as a string.", ret={})
def active_span_context_as_string() -> str:
    """
    Returns:
        The active span context encoded as a string.
    """
    carrier: Dict[str, str] = {}
    if opentracing:
        assert opentracing.tracer.active_span is not None
        opentracing.tracer.inject(
            opentracing.tracer.active_span.context, opentracing.Format.TEXT_MAP, carrier
        )
    return json_encoder.encode(carrier)


def span_context_from_request(request: Request) -> "Optional[opentracing.SpanContext]":
    """Extract an opentracing context from the headers on an HTTP request

    This is useful when we have received an HTTP request from another part of our
    system, and want to link our spans to those of the remote system.
    """
    if not opentracing:
        return None
    header_dict = {
        k.decode(): v[0].decode() for k, v in request.requestHeaders.getAllRawHeaders()
    }
    return opentracing.tracer.extract(opentracing.Format.HTTP_HEADERS, header_dict)


@only_if_tracing
def span_context_from_string(carrier: str) -> Optional["opentracing.SpanContext"]:
    """
    Returns:
        The active span context decoded from a string.
    """
    payload: Dict[str, str] = json_decoder.decode(carrier)
    return opentracing.tracer.extract(opentracing.Format.TEXT_MAP, payload)


@only_if_tracing
def extract_text_map(carrier: Dict[str, str]) -> Optional["opentracing.SpanContext"]:
    """
    Wrapper method for opentracing's tracer.extract for TEXT_MAP.
    Args:
        carrier: a dict possibly containing a span context.

    Returns:
        The active span context extracted from carrier.
    """
    return opentracing.tracer.extract(opentracing.Format.TEXT_MAP, carrier)


# Tracing decorators


def trace(func=None, opname: Optional[str] = None):
    """
    Decorator to trace a function.
    Sets the operation name to that of the function's or that given
    as operation_name. See the module's doc string for usage
    examples.
    """

    def decorator(func):
        if opentracing is None:
            return func  # type: ignore[unreachable]

        _opname = opname if opname else func.__name__

        if inspect.iscoroutinefunction(func):

            @wraps(func)
            async def _trace_inner(*args, **kwargs):
                with start_active_span(_opname):
                    return await func(*args, **kwargs)

        else:
            # The other case here handles both sync functions and those
            # decorated with inlineDeferred.
            @wraps(func)
            def _trace_inner(*args, **kwargs):
                scope = start_active_span(_opname)
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

        return _trace_inner

    if func:
        return decorator(func)
    else:
        return decorator


def tag_args(func: Callable[P, R]) -> Callable[P, R]:
    """
    Tags all of the args to the active span.
    """

    if not opentracing:
        return func

    @wraps(func)
    def _tag_args_inner(*args: P.args, **kwargs: P.kwargs) -> R:
        argspec = inspect.getfullargspec(func)
        for i, arg in enumerate(argspec.args[1:]):
            set_tag("ARG_" + arg, args[i])  # type: ignore[index]
        set_tag("args", args[len(argspec.args) :])  # type: ignore[index]
        set_tag("kwargs", kwargs)
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

    if opentracing is None:
        yield  # type: ignore[unreachable]
        return

    request_tags = {
        SynapseTags.REQUEST_ID: request.get_request_id(),
        tags.SPAN_KIND: tags.SPAN_KIND_RPC_SERVER,
        tags.HTTP_METHOD: request.get_method(),
        tags.HTTP_URL: request.get_redacted_uri(),
        tags.PEER_HOST_IPV6: request.getClientAddress().host,
    }

    request_name = request.request_metrics.name
    context = span_context_from_request(request) if extract_context else None

    # we configure the scope not to finish the span immediately on exit, and instead
    # pass the span into the SynapseRequest, which will finish it once we've finished
    # sending the response to the client.
    scope = start_active_span(request_name, child_of=context, finish_on_close=False)
    request.set_opentracing_span(scope.span)

    with scope:
        inject_response_headers(request.responseHeaders)
        try:
            yield
        finally:
            # We set the operation name again in case its changed (which happens
            # with JsonResource).
            scope.span.set_operation_name(request.request_metrics.name)

            # set the tags *after* the servlet completes, in case it decided to
            # prioritise the span (tags will get dropped on unprioritised spans)
            request_tags[
                SynapseTags.REQUEST_TAG
            ] = request.request_metrics.start_context.tag

            for k, v in request_tags.items():
                scope.span.set_tag(k, v)
