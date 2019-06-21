from opentracing.propagation import Format
import opentracing

from .logcontext import LoggingContext

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