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
from io import BytesIO

from six import text_type
from six.moves import urllib

import treq
from canonicaljson import encode_canonical_json, json
from netaddr import IPAddress
from prometheus_client import Counter
from zope.interface import implementer, provider

from OpenSSL import SSL
from OpenSSL.SSL import VERIFY_NONE
from twisted.internet import defer, protocol, ssl
from twisted.internet.interfaces import (
    IReactorPluggableNameResolver,
    IResolutionReceiver,
)
from twisted.python.failure import Failure
from twisted.web._newclient import ResponseDone
from twisted.web.client import Agent, HTTPConnectionPool, PartialDownloadError, readBody
from twisted.web.http import PotentialDataLoss
from twisted.web.http_headers import Headers

from synapse.api.errors import Codes, HttpResponseException, SynapseError
from synapse.http import (
    QuieterFileBodyProducer,
    cancelled_to_request_timed_out_error,
    redact_uri,
)
from synapse.util.async_helpers import timeout_deferred
from synapse.util.caches import CACHE_SIZE_FACTOR
from synapse.util.logcontext import make_deferred_yieldable

logger = logging.getLogger(__name__)

outgoing_requests_counter = Counter("synapse_http_client_requests", "", ["method"])
incoming_responses_counter = Counter(
    "synapse_http_client_responses", "", ["method", "code"]
)


def check_against_blacklist(ip_address, ip_whitelist, ip_blacklist):
    """
    Args:
        ip_address (netaddr.IPAddress)
        ip_whitelist (netaddr.IPSet)
        ip_blacklist (netaddr.IPSet)
    """
    if ip_address in ip_blacklist:
        if ip_whitelist is None or ip_address not in ip_whitelist:
            return True
    return False


class IPBlacklistingResolver(object):
    """
    A proxy for reactor.nameResolver which only produces non-blacklisted IP
    addresses, preventing DNS rebinding attacks on URL preview.
    """

    def __init__(self, reactor, ip_whitelist, ip_blacklist):
        """
        Args:
            reactor (twisted.internet.reactor)
            ip_whitelist (netaddr.IPSet)
            ip_blacklist (netaddr.IPSet)
        """
        self._reactor = reactor
        self._ip_whitelist = ip_whitelist
        self._ip_blacklist = ip_blacklist

    def resolveHostName(self, recv, hostname, portNumber=0):

        r = recv()
        addresses = []

        def _callback():
            r.resolutionBegan(None)

            has_bad_ip = False
            for i in addresses:
                ip_address = IPAddress(i.host)

                if check_against_blacklist(
                    ip_address, self._ip_whitelist, self._ip_blacklist
                ):
                    logger.info(
                        "Dropped %s from DNS resolution to %s due to blacklist" %
                        (ip_address, hostname)
                    )
                    has_bad_ip = True

            # if we have a blacklisted IP, we'd like to raise an error to block the
            # request, but all we can really do from here is claim that there were no
            # valid results.
            if not has_bad_ip:
                for i in addresses:
                    r.addressResolved(i)
            r.resolutionComplete()

        @provider(IResolutionReceiver)
        class EndpointReceiver(object):
            @staticmethod
            def resolutionBegan(resolutionInProgress):
                pass

            @staticmethod
            def addressResolved(address):
                addresses.append(address)

            @staticmethod
            def resolutionComplete():
                _callback()

        self._reactor.nameResolver.resolveHostName(
            EndpointReceiver, hostname, portNumber=portNumber
        )

        return r


class BlacklistingAgentWrapper(Agent):
    """
    An Agent wrapper which will prevent access to IP addresses being accessed
    directly (without an IP address lookup).
    """

    def __init__(self, agent, reactor, ip_whitelist=None, ip_blacklist=None):
        """
        Args:
            agent (twisted.web.client.Agent): The Agent to wrap.
            reactor (twisted.internet.reactor)
            ip_whitelist (netaddr.IPSet)
            ip_blacklist (netaddr.IPSet)
        """
        self._agent = agent
        self._ip_whitelist = ip_whitelist
        self._ip_blacklist = ip_blacklist

    def request(self, method, uri, headers=None, bodyProducer=None):
        h = urllib.parse.urlparse(uri.decode('ascii'))

        try:
            ip_address = IPAddress(h.hostname)

            if check_against_blacklist(
                ip_address, self._ip_whitelist, self._ip_blacklist
            ):
                logger.info(
                    "Blocking access to %s because of blacklist" % (ip_address,)
                )
                e = SynapseError(403, "IP address blocked by IP blacklist entry")
                return defer.fail(Failure(e))
        except Exception:
            # Not an IP
            pass

        return self._agent.request(
            method, uri, headers=headers, bodyProducer=bodyProducer
        )


class SimpleHttpClient(object):
    """
    A simple, no-frills HTTP client with methods that wrap up common ways of
    using HTTP in Matrix
    """

    def __init__(self, hs, treq_args={}, ip_whitelist=None, ip_blacklist=None):
        """
        Args:
            hs (synapse.server.HomeServer)
            treq_args (dict): Extra keyword arguments to be given to treq.request.
            ip_blacklist (netaddr.IPSet): The IP addresses that are blacklisted that
                we may not request.
            ip_whitelist (netaddr.IPSet): The whitelisted IP addresses, that we can
               request if it were otherwise caught in a blacklist.
        """
        self.hs = hs

        self._ip_whitelist = ip_whitelist
        self._ip_blacklist = ip_blacklist
        self._extra_treq_args = treq_args

        self.user_agent = hs.version_string
        self.clock = hs.get_clock()
        if hs.config.user_agent_suffix:
            self.user_agent = "%s %s" % (self.user_agent, hs.config.user_agent_suffix)

        self.user_agent = self.user_agent.encode('ascii')

        if self._ip_blacklist:
            real_reactor = hs.get_reactor()
            # If we have an IP blacklist, we need to use a DNS resolver which
            # filters out blacklisted IP addresses, to prevent DNS rebinding.
            nameResolver = IPBlacklistingResolver(
                real_reactor, self._ip_whitelist, self._ip_blacklist
            )

            @implementer(IReactorPluggableNameResolver)
            class Reactor(object):
                def __getattr__(_self, attr):
                    if attr == "nameResolver":
                        return nameResolver
                    else:
                        return getattr(real_reactor, attr)

            self.reactor = Reactor()
        else:
            self.reactor = hs.get_reactor()

        # the pusher makes lots of concurrent SSL connections to sygnal, and
        # tends to do so in batches, so we need to allow the pool to keep
        # lots of idle connections around.
        pool = HTTPConnectionPool(self.reactor)
        pool.maxPersistentPerHost = max((100 * CACHE_SIZE_FACTOR, 5))
        pool.cachedConnectionTimeout = 2 * 60

        # The default context factory in Twisted 14.0.0 (which we require) is
        # BrowserLikePolicyForHTTPS which will do regular cert validation
        # 'like a browser'
        self.agent = Agent(
            self.reactor,
            connectTimeout=15,
            contextFactory=self.hs.get_http_client_context_factory(),
            pool=pool,
        )

        if self._ip_blacklist:
            # If we have an IP blacklist, we then install the blacklisting Agent
            # which prevents direct access to IP addresses, that are not caught
            # by the DNS resolution.
            self.agent = BlacklistingAgentWrapper(
                self.agent,
                self.reactor,
                ip_whitelist=self._ip_whitelist,
                ip_blacklist=self._ip_blacklist,
            )

    @defer.inlineCallbacks
    def request(self, method, uri, data=None, headers=None):
        """
        Args:
            method (str): HTTP method to use.
            uri (str): URI to query.
            data (bytes): Data to send in the request body, if applicable.
            headers (t.w.http_headers.Headers): Request headers.

        Raises:
            SynapseError: If the IP is blacklisted.
        """
        # A small wrapper around self.agent.request() so we can easily attach
        # counters to it
        outgoing_requests_counter.labels(method).inc()

        # log request but strip `access_token` (AS requests for example include this)
        logger.info("Sending request %s %s", method, redact_uri(uri))

        try:
            body_producer = None
            if data is not None:
                body_producer = QuieterFileBodyProducer(BytesIO(data))

            request_deferred = treq.request(
                method,
                uri,
                agent=self.agent,
                data=body_producer,
                headers=headers,
                **self._extra_treq_args
            )
            request_deferred = timeout_deferred(
                request_deferred,
                60,
                self.hs.get_reactor(),
                cancelled_to_request_timed_out_error,
            )
            response = yield make_deferred_yieldable(request_deferred)

            incoming_responses_counter.labels(method, response.code).inc()
            logger.info(
                "Received response to %s %s: %s", method, redact_uri(uri), response.code
            )
            defer.returnValue(response)
        except Exception as e:
            incoming_responses_counter.labels(method, "ERR").inc()
            logger.info(
                "Error sending request to  %s %s: %s %s",
                method,
                redact_uri(uri),
                type(e).__name__,
                e.args[0],
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

        query_bytes = urllib.parse.urlencode(encode_urlencode_args(args), True).encode(
            "utf8"
        )

        actual_headers = {
            b"Content-Type": [b"application/x-www-form-urlencoded"],
            b"User-Agent": [self.user_agent],
        }
        if headers:
            actual_headers.update(headers)

        response = yield self.request(
            "POST", uri, headers=Headers(actual_headers), data=query_bytes
        )

        body = yield make_deferred_yieldable(readBody(response))

        if 200 <= response.code < 300:
            defer.returnValue(json.loads(body))
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
            "POST", uri, headers=Headers(actual_headers), data=json_str
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
            "PUT", uri, headers=Headers(actual_headers), data=json_str
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

        actual_headers = {b"User-Agent": [self.user_agent]}
        if headers:
            actual_headers.update(headers)

        response = yield self.request("GET", uri, headers=Headers(actual_headers))

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

        actual_headers = {b"User-Agent": [self.user_agent]}
        if headers:
            actual_headers.update(headers)

        response = yield self.request("GET", url, headers=Headers(actual_headers))

        resp_headers = dict(response.headers.getAllRawHeaders())

        if (
            b'Content-Length' in resp_headers
            and int(resp_headers[b'Content-Length'][0]) > max_size
        ):
            logger.warn("Requested URL is too large > %r bytes" % (self.max_size,))
            raise SynapseError(
                502,
                "Requested file is too large > %r bytes" % (self.max_size,),
                Codes.TOO_LARGE,
            )

        if response.code > 299:
            logger.warn("Got %d when downloading %s" % (response.code, url))
            raise SynapseError(502, "Got error %d" % (response.code,), Codes.UNKNOWN)

        # TODO: if our Content-Type is HTML or something, just read the first
        # N bytes into RAM rather than saving it all to disk only to read it
        # straight back in again

        try:
            length = yield make_deferred_yieldable(
                _readBodyToFile(response, output_stream, max_size)
            )
        except Exception as e:
            logger.exception("Failed to download body")
            raise SynapseError(
                502, ("Failed to download remote body: %s" % e), Codes.UNKNOWN
            )

        defer.returnValue(
            (
                length,
                resp_headers,
                response.request.absoluteURI.decode('ascii'),
                response.code,
            )
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
            self.deferred.errback(
                SynapseError(
                    502,
                    "Requested file is too large > %r bytes" % (self.max_size,),
                    Codes.TOO_LARGE,
                )
            )
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
            headers=Headers(
                {
                    b"Content-Type": [b"application/x-www-form-urlencoded"],
                    b"User-Agent": [self.user_agent],
                }
            ),
        )

        try:
            body = yield make_deferred_yieldable(readBody(response))
            defer.returnValue(body)
        except PartialDownloadError as e:
            # twisted dislikes google's response, no content length.
            defer.returnValue(e.response)


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
