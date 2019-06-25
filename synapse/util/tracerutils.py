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

import opentracing
from opentracing.propagation import Format


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


def inject_span_context(headers, span):
    """
    Injects a span context into twisted headers inplace
    args:
        headers (twisted.web.http_headers.Headers)
        span (opentracing.Span)

    note:
        The headers set by the tracer are custom to the tracer implementation which
        should be unique enough that they don't interfere with any headers set by
        synapse or twisted. If we're still using jaeger these headers would be those
        here:
        https://github.com/jaegertracing/jaeger-client-python/blob/master/jaeger_client/constants.py
    """
    carrier = {}
    carrier = opentracing.tracer.inject(span, Format.HTTP_HEADERS, {})

    for key, value in carrier:
        headers.addRawHeaders(key, value)


# TODO: Implement whitelisting
def request_from_whitelisted_homeserver(request):
    pass


# TODO: Implement whitelisting
def user_whitelisted(request):
    pass
