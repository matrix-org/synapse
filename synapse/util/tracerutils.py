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

logger = logging.getLogger(__name__)

import opentracing
from opentracing.propagation import Format

import re

# block everything by default


class TracerUtil:
    _homeserver_whitelist = None

    @staticmethod
    def set_homeserver_whitelist(homeserver_whitelist):
        """Sets the whitelist

        Args:
            homeserver_whitelist (iterable of strings): regex of whitelisted homeservers
        """
        if homeserver_whitelist:
            # Makes a single regex which accepts all passed in regexes in the list
            TracerUtil._homeserver_whitelist = re.compile(
                "({})".format(")|(".join(homeserver_whitelist))
            )
            logger.info("Set whitelist to {}".format(TracerUtil._homeserver_whitelist))

    @staticmethod
    def whitelisted_homeserver(destination):
        if TracerUtil._homeserver_whitelist:
            return TracerUtil._homeserver_whitelist.match(destination)
        return False

    @staticmethod
    def extract_span_context(headers):
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
        return opentracing.tracer.extract(Format.HTTP_HEADERS, header_dict)

    @staticmethod
    def inject_span_context(headers, span, destination):
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
        carrier = {}
        opentracing.tracer.inject(span, Format.HTTP_HEADERS, carrier)

        for key, value in carrier.items():
            headers.addRawHeaders(key, value)

    @staticmethod
    def inject_span_context_byte_dict(headers, span, destination):
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
            logger.info("{}".format(TracerUtil._homeserver_whitelist))
            return

        carrier = {}
        opentracing.tracer.inject(span, Format.HTTP_HEADERS, carrier)

        for key, value in carrier.items():
            headers[key.encode()] = [value.encode()]
