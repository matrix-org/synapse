# -*- coding: utf-8 -*-
# Copyright 2014-2016 OpenMarket Ltd
# Copyright 2018 New Vector Ltd
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

import logging

from six import text_type
from six.moves import urllib

import treq
from canonicaljson import encode_canonical_json, json
from prometheus_client import Counter

from OpenSSL import SSL
from OpenSSL.SSL import VERIFY_NONE
from twisted.internet import defer, protocol, reactor, ssl
from twisted.internet.endpoints import HostnameEndpoint, wrapClientTLS
from twisted.web._newclient import ResponseDone
from twisted.web.client import (
    Agent,
    BrowserLikeRedirectAgent,
    ContentDecoderAgent,
    GzipDecoder,
    HTTPConnectionPool,
    PartialDownloadError,
    readBody,
)
from twisted.web.http import PotentialDataLoss
from twisted.web.http_headers import Headers

from synapse.api.errors import Codes, HttpResponseException, SynapseError
from synapse.http import cancelled_to_request_timed_out_error, redact_uri
from synapse.http.endpoint import SpiderEndpoint
from synapse.util.async_helpers import add_timeout_to_deferred
from synapse.util.caches import CACHE_SIZE_FACTOR
from synapse.util.logcontext import make_deferred_yieldable

logger = logging.getLogger(__name__)

outgoing_requests_counter = Counter("synapse_http_client_requests", "", ["method"])
incoming_responses_counter = Counter("synapse_http_client_responses", "",
                                     ["method", "code"])


class SimpleHttpClient(object):
    """
    A simple, no-frills HTTP client with methods that wrap up common ways of
    using HTTP in Matrix
    """
    def __init__(self, hs):
        self.hs = hs

        pool = HTTPConnectionPool(reactor)

        # the pusher makes lots of concurrent SSL connections to sygnal, and
        # tends to do so in batches, so we need to allow the pool to keep lots
        # of idle connections around.
        pool.maxPersistentPerHost = max((100 * CACHE_SIZE_FACTOR, 5))
        pool.cachedConnectionTimeout = 2 * 60

        # The default context factory in Twisted 14.0.0 (which we require) is
        # BrowserLikePolicyForHTTPS which will do regular cert validation
        # 'like a browser'
        self.agent = Agent(
            reactor,
            connectTimeout=15,
            contextFactory=hs.get_http_client_context_factory(),
            pool=pool,
        )
        self.user_agent = hs.version_string
        self.clock = hs.get_clock()
        if hs.config.user_agent_suffix:
            self.user_agent = "%s %s" % (self.user_agent, hs.config.user_agent_suffix,)

        self.user_agent = self.user_agent.encode('ascii')

    @defer.inlineCallbacks
    def request(self, method, uri, data=b'', headers=None):
        # A small wrapper around self.agent.request() so we can easily attach
        # counters to it
        outgoing_requests_counter.labels(method).inc()

        # log request but strip `access_token` (AS requests for example include this)
        logger.info("Sending request %s %s", method, redact_uri(uri))

        try:
            request_deferred = treq.request(
                method, uri, agent=self.agent, data=data, headers=headers
            )
            add_timeout_to_deferred(
                request_deferred, 60, self.hs.get_reactor(),
                cancelled_to_request_timed_out_error,
            )
            response = yield make_deferred_yieldable(request_deferred)

            incoming_responses_counter.labels(method, response.code).inc()
            logger.info(
                "Received response to  %s %s: %s",
                method, redact_uri(uri), response.code
            )
            defer.returnValue(response)
        except Exception as e:
            incoming_responses_counter.labels(method, "ERR").inc()
            logger.info(
                "Error sending request to  %s %s: %s %s",
                method, redact_uri(uri), type(e).__name__, e.args[0]
            )
            raise

    @defer.inlineCallbacks
    def post_urlencoded_get_json(self, uri, args={}, headers=None):
        """
        Args:
            uri (str):
            args (dict[str, str|List[str]]): query params
            headers (dict[str, List[str]]|None): If not None, a map from
               header name to a list of values for that header

        Returns:
            Deferred[object]: parsed json

        Raises:
            HttpResponseException: On a non-2xx HTTP response.

            ValueError: if the response was not JSON
        """

        # TODO: Do we ever want to log message contents?
        logger.debug("post_urlencoded_get_json args: %s", args)

        query_bytes = urllib.parse.urlencode(
            encode_urlencode_args(args), True).encode("utf8")

        actual_headers = {
            b"Content-Type": [b"application/x-www-form-urlencoded"],
            b"User-Agent": [self.user_agent],
        }
        if headers:
            actual_headers.update(headers)

        response = yield self.request(
            "POST",
            uri,
            headers=Headers(actual_headers),
            data=query_bytes
        )

        if 200 <= response.code < 300:
            body = yield make_deferred_yieldable(treq.json_content(response))
            defer.returnValue(body)
        else:
            raise HttpResponseException(response.code, response.phrase, body)

    @defer.inlineCallbacks
    def post_json_get_json(self, uri, post_json, headers=None):
        """

        Args:
            uri (str):
            post_json (object):
            headers (dict[str, List[str]]|None): If not None, a map from
               header name to a list of values for that header

        Returns:
            Deferred[object]: parsed json

        Raises:
            HttpResponseException: On a non-2xx HTTP response.

            ValueError: if the response was not JSON
        """
        json_str = encode_canonical_json(post_json)

        logger.debug("HTTP POST %s -> %s", json_str, uri)

        actual_headers = {
            b"Content-Type": [b"application/json"],
            b"User-Agent": [self.user_agent],
        }
        if headers:
            actual_headers.update(headers)

        response = yield self.request(
            "POST",
            uri,
            headers=Headers(actual_headers),
            data=json_str
        )

        body = yield make_deferred_yieldable(readBody(response))

        if 200 <= response.code < 300:
            defer.returnValue(json.loads(body))
        else:
            raise HttpResponseException(response.code, response.phrase, body)

    @defer.inlineCallbacks
    def get_json(self, uri, args={}, headers=None):
        """ Gets some json from the given URI.

        Args:
            uri (str): The URI to request, not including query parameters
            args (dict): A dictionary used to create query strings, defaults to
                None.
                **Note**: The value of each key is assumed to be an iterable
                and *not* a string.
            headers (dict[str, List[str]]|None): If not None, a map from
               header name to a list of values for that header
        Returns:
            Deferred: Succeeds when we get *any* 2xx HTTP response, with the
            HTTP body as JSON.
        Raises:
            HttpResponseException On a non-2xx HTTP response.

            ValueError: if the response was not JSON
        """
        body = yield self.get_raw(uri, args, headers=headers)
        defer.returnValue(json.loads(body))

    @defer.inlineCallbacks
    def put_json(self, uri, json_body, args={}, headers=None):
        """ Puts some json to the given URI.

        Args:
            uri (str): The URI to request, not including query parameters
            json_body (dict): The JSON to put in the HTTP body,
            args (dict): A dictionary used to create query strings, defaults to
                None.
                **Note**: The value of each key is assumed to be an iterable
                and *not* a string.
            headers (dict[str, List[str]]|None): If not None, a map from
               header name to a list of values for that header
        Returns:
            Deferred: Succeeds when we get *any* 2xx HTTP response, with the
            HTTP body as JSON.
        Raises:
            HttpResponseException On a non-2xx HTTP response.

            ValueError: if the response was not JSON
        """
        if len(args):
            query_bytes = urllib.parse.urlencode(args, True)
            uri = "%s?%s" % (uri, query_bytes)

        json_str = encode_canonical_json(json_body)

        actual_headers = {
            b"Content-Type": [b"application/json"],
            b"User-Agent": [self.user_agent],
        }
        if headers:
            actual_headers.update(headers)

        response = yield self.request(
            "PUT",
            uri,
            headers=Headers(actual_headers),
            data=json_str
        )

        body = yield make_deferred_yieldable(readBody(response))

        if 200 <= response.code < 300:
            defer.returnValue(json.loads(body))
        else:
            raise HttpResponseException(response.code, response.phrase, body)

    @defer.inlineCallbacks
    def get_raw(self, uri, args={}, headers=None):
        """ Gets raw text from the given URI.

        Args:
            uri (str): The URI to request, not including query parameters
            args (dict): A dictionary used to create query strings, defaults to
                None.
                **Note**: The value of each key is assumed to be an iterable
                and *not* a string.
            headers (dict[str, List[str]]|None): If not None, a map from
               header name to a list of values for that header
        Returns:
            Deferred: Succeeds when we get *any* 2xx HTTP response, with the
            HTTP body at text.
        Raises:
            HttpResponseException on a non-2xx HTTP response.
        """
        if len(args):
            query_bytes = urllib.parse.urlencode(args, True)
            uri = "%s?%s" % (uri, query_bytes)

        actual_headers = {
            b"User-Agent": [self.user_agent],
        }
        if headers:
            actual_headers.update(headers)

        response = yield self.request(
            "GET",
            uri,
            headers=Headers(actual_headers),
        )

        body = yield make_deferred_yieldable(readBody(response))

        if 200 <= response.code < 300:
            defer.returnValue(body)
        else:
            raise HttpResponseException(response.code, response.phrase, body)

    # XXX: FIXME: This is horribly copy-pasted from matrixfederationclient.
    # The two should be factored out.

    @defer.inlineCallbacks
    def get_file(self, url, output_stream, max_size=None, headers=None):
        """GETs a file from a given URL
        Args:
            url (str): The URL to GET
            output_stream (file): File to write the response body to.
            headers (dict[str, List[str]]|None): If not None, a map from
               header name to a list of values for that header
        Returns:
            A (int,dict,string,int) tuple of the file length, dict of the response
            headers, absolute URI of the response and HTTP response code.
        """

        actual_headers = {
            b"User-Agent": [self.user_agent],
        }
        if headers:
            actual_headers.update(headers)

        response = yield self.request(
            "GET",
            url,
            headers=Headers(actual_headers),
        )

        resp_headers = dict(response.headers.getAllRawHeaders())

        if (b'Content-Length' in resp_headers and
                int(resp_headers[b'Content-Length']) > max_size):
            logger.warn("Requested URL is too large > %r bytes" % (self.max_size,))
            raise SynapseError(
                502,
                "Requested file is too large > %r bytes" % (self.max_size,),
                Codes.TOO_LARGE,
            )

        if response.code > 299:
            logger.warn("Got %d when downloading %s" % (response.code, url))
            raise SynapseError(
                502,
                "Got error %d" % (response.code,),
                Codes.UNKNOWN,
            )

        # TODO: if our Content-Type is HTML or something, just read the first
        # N bytes into RAM rather than saving it all to disk only to read it
        # straight back in again

        try:
            length = yield make_deferred_yieldable(_readBodyToFile(
                response, output_stream, max_size,
            ))
        except Exception as e:
            logger.exception("Failed to download body")
            raise SynapseError(
                502,
                ("Failed to download remote body: %s" % e),
                Codes.UNKNOWN,
            )

        defer.returnValue(
            (
                length,
                resp_headers,
                response.request.absoluteURI.decode('ascii'),
                response.code,
            ),
        )


# XXX: FIXME: This is horribly copy-pasted from matrixfederationclient.
# The two should be factored out.

class _ReadBodyToFileProtocol(protocol.Protocol):
    def __init__(self, stream, deferred, max_size):
        self.stream = stream
        self.deferred = deferred
        self.length = 0
        self.max_size = max_size

    def dataReceived(self, data):
        self.stream.write(data)
        self.length += len(data)
        if self.max_size is not None and self.length >= self.max_size:
            self.deferred.errback(SynapseError(
                502,
                "Requested file is too large > %r bytes" % (self.max_size,),
                Codes.TOO_LARGE,
            ))
            self.deferred = defer.Deferred()
            self.transport.loseConnection()

    def connectionLost(self, reason):
        if reason.check(ResponseDone):
            self.deferred.callback(self.length)
        elif reason.check(PotentialDataLoss):
            # stolen from https://github.com/twisted/treq/pull/49/files
            # http://twistedmatrix.com/trac/ticket/4840
            self.deferred.callback(self.length)
        else:
            self.deferred.errback(reason)


# XXX: FIXME: This is horribly copy-pasted from matrixfederationclient.
# The two should be factored out.

def _readBodyToFile(response, stream, max_size):
    d = defer.Deferred()
    response.deliverBody(_ReadBodyToFileProtocol(stream, d, max_size))
    return d


class CaptchaServerHttpClient(SimpleHttpClient):
    """
    Separate HTTP client for talking to google's captcha servers
    Only slightly special because accepts partial download responses

    used only by c/s api v1
    """

    @defer.inlineCallbacks
    def post_urlencoded_get_raw(self, url, args={}):
        query_bytes = urllib.parse.urlencode(encode_urlencode_args(args), True)

        response = yield self.request(
            "POST",
            url,
            data=query_bytes,
            headers=Headers({
                b"Content-Type": [b"application/x-www-form-urlencoded"],
                b"User-Agent": [self.user_agent],
            })
        )

        try:
            body = yield make_deferred_yieldable(readBody(response))
            defer.returnValue(body)
        except PartialDownloadError as e:
            # twisted dislikes google's response, no content length.
            defer.returnValue(e.response)


class SpiderEndpointFactory(object):
    def __init__(self, hs):
        self.blacklist = hs.config.url_preview_ip_range_blacklist
        self.whitelist = hs.config.url_preview_ip_range_whitelist
        self.policyForHTTPS = hs.get_http_client_context_factory()

    def endpointForURI(self, uri):
        logger.info("Getting endpoint for %s", uri.toBytes())

        if uri.scheme == b"http":
            endpoint_factory = HostnameEndpoint
        elif uri.scheme == b"https":
            tlsCreator = self.policyForHTTPS.creatorForNetloc(uri.host, uri.port)

            def endpoint_factory(reactor, host, port, **kw):
                return wrapClientTLS(
                    tlsCreator,
                    HostnameEndpoint(reactor, host, port, **kw))
        else:
            logger.warn("Can't get endpoint for unrecognised scheme %s", uri.scheme)
            return None
        return SpiderEndpoint(
            reactor, uri.host, uri.port, self.blacklist, self.whitelist,
            endpoint=endpoint_factory, endpoint_kw_args=dict(timeout=15),
        )


class SpiderHttpClient(SimpleHttpClient):
    """
    Separate HTTP client for spidering arbitrary URLs.
    Special in that it follows retries and has a UA that looks
    like a browser.

    used by the preview_url endpoint in the content repo.
    """
    def __init__(self, hs):
        SimpleHttpClient.__init__(self, hs)
        # clobber the base class's agent and UA:
        self.agent = ContentDecoderAgent(
            BrowserLikeRedirectAgent(
                Agent.usingEndpointFactory(
                    reactor,
                    SpiderEndpointFactory(hs)
                )
            ), [(b'gzip', GzipDecoder)]
        )
        # We could look like Chrome:
        # self.user_agent = ("Mozilla/5.0 (%s) (KHTML, like Gecko)
        #                   Chrome Safari" % hs.version_string)


def encode_urlencode_args(args):
    return {k: encode_urlencode_arg(v) for k, v in args.items()}


def encode_urlencode_arg(arg):
    if isinstance(arg, text_type):
        return arg.encode('utf-8')
    elif isinstance(arg, list):
        return [encode_urlencode_arg(i) for i in arg]
    else:
        return arg


def _print_ex(e):
    if hasattr(e, "reasons") and e.reasons:
        for ex in e.reasons:
            _print_ex(ex)
    else:
        logger.exception(e)


class InsecureInterceptableContextFactory(ssl.ContextFactory):
    """
    Factory for PyOpenSSL SSL contexts which accepts any certificate for any domain.

    Do not use this since it allows an attacker to intercept your communications.
    """

    def __init__(self):
        self._context = SSL.Context(SSL.SSLv23_METHOD)
        self._context.set_verify(VERIFY_NONE, lambda *_: None)

    def getContext(self, hostname=None, port=None):
        return self._context

    def creatorForNetloc(self, hostname, port):
        return self
