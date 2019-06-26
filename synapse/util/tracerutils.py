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

import logging
import re
from functools import wraps

logger = logging.getLogger(__name__)


def only_if_tracing(func):
    """Executes the function only if we're tracing. Otherwise return.
    Assumes the function wrapped may return None"""

    @wraps(func)
    def f(cls, *args, **kwargs):
        if cls._opentracing:
            return func(cls, *args, **kwargs)
        else:
            return

    return f


class TracerUtil(object):
    _opentracing = None
    _opentracing_formats = None

    # Block everything by default
    _homeserver_whitelist = None

    @classmethod
    def init_tracer(cls, config):
        """Set the whitelists and initialise the JaegerClient tracer

        Args:
            config (Config)
            The config used by the homserver. Here it's used to set the service
            name to the homeserver's.
        """
        if not config.tracer_config.get("tracer_enabled", False):
            # We don't have a tracer
            return

        cls.import_opentracing()
        cls.set_tags()
        cls.setup_tracing(config)

    @classmethod
    def import_opentracing(cls):
        try:
            # Try to import the tracer. If it's not there we want to throw an eror
            import opentracing
        except ImportError as e:
            logger.error(
                "The server has been configure to use opentracing but "
                "the {} module has not been installed.".format(e.name)
            )
            raise

        cls._opentracing = opentracing
        cls.set_tags()

    @classmethod
    def setup_tracing(cls, config):
        try:
            from jaeger_client import Config as JaegerConfig
            from synapse.util.scopecontextmanager import LogContextScopeManager
        except ImportError as e:
            logger.error(
                "The server has been configure to use opentracing but "
                "the {} module has not been installed.".format(e.name)
            )
            raise

        # Include the worker name
        name = config.worker_name if config.worker_name else "master"

        cls.set_homeserver_whitelist(config.tracer_config["homeserver_whitelist"])
        jaeger_config = JaegerConfig(
            config={"sampler": {"type": "const", "param": 1}, "logging": True},
            service_name="{} {}".format(config.server_name, name),
            scope_manager=LogContextScopeManager(config),
        )
        jaeger_config.initialize_tracer()

    class Tags(object):
        """wrapper of opentracings tags. We need to have them if we
        want to reference them without opentracing around. Clearly they
        should never actually show up in a trace. `set_tags` overwrites
        these with the correct ones."""

        COMPONENT = "invlalid-tag"
        DATABASE_INSTANCE = "invlalid-tag"
        DATABASE_STATEMENT = "invlalid-tag"
        DATABASE_TYPE = "invlalid-tag"
        DATABASE_USER = "invlalid-tag"
        ERROR = "invlalid-tag"
        HTTP_METHOD = "invlalid-tag"
        HTTP_STATUS_CODE = "invlalid-tag"
        HTTP_URL = "invlalid-tag"
        MESSAGE_BUS_DESTINATION = "invlalid-tag"
        PEER_ADDRESS = "invlalid-tag"
        PEER_HOSTNAME = "invlalid-tag"
        PEER_HOST_IPV4 = "invlalid-tag"
        PEER_HOST_IPV6 = "invlalid-tag"
        PEER_PORT = "invlalid-tag"
        PEER_SERVICE = "invlalid-tag"
        SAMPLING_PRIORITY = "invlalid-tag"
        SERVICE = "invlalid-tag"
        SPAN_KIND = "invlalid-tag"
        SPAN_KIND_CONSUMER = "invlalid-tag"
        SPAN_KIND_PRODUCER = "invlalid-tag"
        SPAN_KIND_RPC_CLIENT = "invlalid-tag"
        SPAN_KIND_RPC_SERVER = "invlalid-tag"

    @classmethod
    @only_if_tracing
    def set_tags(cls):
        cls.Tags = cls._opentracing.tags

    # Could use kwargs but I want these to be explicit
    @classmethod
    @only_if_tracing
    def start_active_span(
        cls,
        operation_name,
        child_of=None,
        references=None,
        tags=None,
        start_time=None,
        ignore_active_span=False,
        finish_on_close=True,
    ):
        # We need to enter the scope here for the logcontext to become active
        cls._opentracing.tracer.start_active_span(
            operation_name,
            child_of=child_of,
            references=references,
            tags=tags,
            start_time=start_time,
            ignore_active_span=ignore_active_span,
            finish_on_close=finish_on_close,
        ).__enter__()

    @classmethod
    @only_if_tracing
    def close_active_span(cls):
        cls._opentracing.tracer.scope_manager.active.__exit__(None, None, None)

    @classmethod
    @only_if_tracing
    def set_tag(cls, key, value):
        cls._opentracing.tracer.active_span.set_tag(key, value)

    @classmethod
    @only_if_tracing
    def log_kv(cls, key_values, timestamp=None):
        cls._opentracing.tracer.active_span.log_kv(key_values, timestamp)

    # Note: we don't have a get baggage items because we're trying to hide all
    # scope and span state from synapse. I think this method may also be useless
    # as a result
    @classmethod
    @only_if_tracing
    def set_baggage_item(cls, key, value):
        cls._opentracing.tracer.active_span.set_baggage_item(key, value)

    @classmethod
    @only_if_tracing
    def set_operation_name(cls, operation_name):
        cls._opentracing.tracer.active_span.set_operation_name(operation_name)

    @classmethod
    @only_if_tracing
    def set_homeserver_whitelist(cls, homeserver_whitelist):
        """Sets the whitelist

        Args:
            homeserver_whitelist (iterable of strings): regex of whitelisted homeservers
        """
        if homeserver_whitelist:
            # Makes a single regex which accepts all passed in regexes in the list
            cls._homeserver_whitelist = re.compile(
                "({})".format(")|(".join(homeserver_whitelist))
            )

    @classmethod
    @only_if_tracing
    def whitelisted_homeserver(cls, destination):
        if cls._homeserver_whitelist:
            return cls._homeserver_whitelist.match(destination)
        return False

    @classmethod
    @only_if_tracing
    def start_active_span_from_context(
        cls,
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
        context = cls._opentracing.tracer.extract(
            cls._opentracing.Format.HTTP_HEADERS, header_dict
        )

        cls._opentracing.tracer.start_active_span(
            operation_name,
            child_of=context,
            references=references,
            tags=tags,
            start_time=start_time,
            ignore_active_span=ignore_active_span,
            finish_on_close=finish_on_close,
        )

    @classmethod
    @only_if_tracing
    def inject_active_span_twisted_headers(cls, headers, destination):
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

        if not TracerUtil.whitelisted_homeserver(destination):
            return

        span = cls._opentracing.tracer.active_span
        carrier = {}
        cls._opentracing.tracer.inject(
            span, cls._opentracing.Format.HTTP_HEADERS, carrier
        )

        for key, value in carrier.items():
            headers.addRawHeaders(key, value)

    @classmethod
    @only_if_tracing
    def inject_active_span_byte_dict(cls, headers, destination):
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
        if not TracerUtil.whitelisted_homeserver(destination):
            return

        span = cls._opentracing.tracer.active_span

        carrier = {}
        cls._opentracing.tracer.inject(
            span, cls._opentracing.Format.HTTP_HEADERS, carrier
        )

        for key, value in carrier.items():
            headers[key.encode()] = [value.encode()]
