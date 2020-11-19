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
import urllib
from io import BytesIO
from typing import (
    Any,
    BinaryIO,
    Dict,
    Iterable,
    List,
    Mapping,
    Optional,
    Sequence,
    Tuple,
    Union,
)

import treq
from canonicaljson import encode_canonical_json
from netaddr import IPAddress
from prometheus_client import Counter
from zope.interface import implementer, provider

from OpenSSL import SSL
from OpenSSL.SSL import VERIFY_NONE
from twisted.internet import defer, error as twisted_error, protocol, ssl
from twisted.internet.interfaces import (
    IReactorPluggableNameResolver,
    IResolutionReceiver,
)
from twisted.internet.task import Cooperator
from twisted.python.failure import Failure
from twisted.web._newclient import ResponseDone
from twisted.web.client import (
    Agent,
    HTTPConnectionPool,
    ResponseNeverReceived,
    readBody,
)
from twisted.web.http import PotentialDataLoss
from twisted.web.http_headers import Headers
from twisted.web.iweb import IResponse

from synapse.api.errors import Codes, HttpResponseException, SynapseError
from synapse.http import QuieterFileBodyProducer, RequestTimedOutError, redact_uri
from synapse.http.proxyagent import ProxyAgent
from synapse.logging.context import make_deferred_yieldable
from synapse.logging.opentracing import set_tag, start_active_span, tags
from synapse.util import json_decoder
from synapse.util.async_helpers import timeout_deferred

logger = logging.getLogger(__name__)

outgoing_requests_counter = Counter("synapse_http_client_requests", "", ["method"])
incoming_responses_counter = Counter(
    "synapse_http_client_responses", "", ["method", "code"]
)

# the type of the headers list, to be passed to the t.w.h.Headers.
# Actually we can mix str and bytes keys, but Mapping treats 'key' as invariant so
# we simplify.
RawHeaders = Union[Mapping[str, "RawHeaderValue"], Mapping[bytes, "RawHeaderValue"]]

# the value actually has to be a List, but List is invariant so we can't specify that
# the entries can either be Lists or bytes.
RawHeaderValue = Sequence[Union[str, bytes]]

# the type of the query params, to be passed into `urlencode`
QueryParamValue = Union[str, bytes, Iterable[Union[str, bytes]]]
QueryParams = Union[Mapping[str, QueryParamValue], Mapping[bytes, QueryParamValue]]


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


_EPSILON = 0.00000001


def _make_scheduler(reactor):
    """Makes a schedular suitable for a Cooperator using the given reactor.

    (This is effectively just a copy from `twisted.internet.task`)
    """

    def _scheduler(x):
        return reactor.callLater(_EPSILON, x)

    return _scheduler


class IPBlacklistingResolver:
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
                        "Dropped %s from DNS resolution to %s due to blacklist"
                        % (ip_address, hostname)
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
        class EndpointReceiver:
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
        h = urllib.parse.urlparse(uri.decode("ascii"))

        try:
            ip_address = IPAddress(h.hostname)

            if check_against_blacklist(
                ip_address, self._ip_whitelist, self._ip_blacklist
            ):
                logger.info("Blocking access to %s due to blacklist" % (ip_address,))
                e = SynapseError(403, "IP address blocked by IP blacklist entry")
                return defer.fail(Failure(e))
        except Exception:
            # Not an IP
            pass

        return self._agent.request(
            method, uri, headers=headers, bodyProducer=bodyProducer
        )


class SimpleHttpClient:
    """
    A simple, no-frills HTTP client with methods that wrap up common ways of
    using HTTP in Matrix
    """

    def __init__(
        self,
        hs,
        treq_args={},
        ip_whitelist=None,
        ip_blacklist=None,
        http_proxy=None,
        https_proxy=None,
    ):
        """
        Args:
            hs (synapse.server.HomeServer)
            treq_args (dict): Extra keyword arguments to be given to treq.request.
            ip_blacklist (netaddr.IPSet): The IP addresses that are blacklisted that
                we may not request.
            ip_whitelist (netaddr.IPSet): The whitelisted IP addresses, that we can
               request if it were otherwise caught in a blacklist.
            http_proxy (bytes): proxy server to use for http connections. host[:port]
            https_proxy (bytes): proxy server to use for https connections. host[:port]
        """
        self.hs = hs

        self._ip_whitelist = ip_whitelist
        self._ip_blacklist = ip_blacklist
        self._extra_treq_args = treq_args

        self.user_agent = hs.version_string
        self.clock = hs.get_clock()
        if hs.config.user_agent_suffix:
            self.user_agent = "%s %s" % (self.user_agent, hs.config.user_agent_suffix)

        # We use this for our body producers to ensure that they use the correct
        # reactor.
        self._cooperator = Cooperator(scheduler=_make_scheduler(hs.get_reactor()))

        self.user_agent = self.user_agent.encode("ascii")

        if self._ip_blacklist:
            real_reactor = hs.get_reactor()
            # If we have an IP blacklist, we need to use a DNS resolver which
            # filters out blacklisted IP addresses, to prevent DNS rebinding.
            nameResolver = IPBlacklistingResolver(
                real_reactor, self._ip_whitelist, self._ip_blacklist
            )

            @implementer(IReactorPluggableNameResolver)
            class Reactor:
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
        # XXX: The justification for using the cache factor here is that larger instances
        # will need both more cache and more connections.
        # Still, this should probably be a separate dial
        pool.maxPersistentPerHost = max((100 * hs.config.caches.global_factor, 5))
        pool.cachedConnectionTimeout = 2 * 60

        self.agent = ProxyAgent(
            self.reactor,
            connectTimeout=15,
            contextFactory=self.hs.get_http_client_context_factory(),
            pool=pool,
            http_proxy=http_proxy,
            https_proxy=https_proxy,
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

    async def request(
        self,
        method: str,
        uri: str,
        data: Optional[bytes] = None,
        headers: Optional[Headers] = None,
    ) -> IResponse:
        """
        Args:
            method: HTTP method to use.
            uri: URI to query.
            data: Data to send in the request body, if applicable.
            headers: Request headers.

        Returns:
            Response object, once the headers have been read.

        Raises:
            RequestTimedOutError if the request times out before the headers are read

        """
        outgoing_requests_counter.labels(method).inc()

        # log request but strip `access_token` (AS requests for example include this)
        logger.debug("Sending request %s %s", method, redact_uri(uri))

        with start_active_span(
            "outgoing-client-request",
            tags={
                tags.SPAN_KIND: tags.SPAN_KIND_RPC_CLIENT,
                tags.HTTP_METHOD: method,
                tags.HTTP_URL: uri,
            },
            finish_on_close=True,
        ):
            try:
                body_producer = None
                if data is not None:
                    body_producer = QuieterFileBodyProducer(
                        BytesIO(data), cooperator=self._cooperator,
                    )

                request_deferred = treq.request(
                    method,
                    uri,
                    agent=self.agent,
                    data=body_producer,
                    headers=headers,
                    **self._extra_treq_args,
                )  # type: defer.Deferred

                # we use our own timeout mechanism rather than treq's as a workaround
                # for https://twistedmatrix.com/trac/ticket/9534.
                request_deferred = timeout_deferred(
                    request_deferred, 60, self.hs.get_reactor(),
                )

                # turn timeouts into RequestTimedOutErrors
                request_deferred.addErrback(_timeout_to_request_timed_out_error)

                response = await make_deferred_yieldable(request_deferred)

                incoming_responses_counter.labels(method, response.code).inc()
                logger.info(
                    "Received response to %s %s: %s",
                    method,
                    redact_uri(uri),
                    response.code,
                )
                return response
            except Exception as e:
                incoming_responses_counter.labels(method, "ERR").inc()
                logger.info(
                    "Error sending request to  %s %s: %s %s",
                    method,
                    redact_uri(uri),
                    type(e).__name__,
                    e.args[0],
                )
                set_tag(tags.ERROR, True)
                set_tag("error_reason", e.args[0])
                raise

    async def post_urlencoded_get_json(
        self,
        uri: str,
        args: Mapping[str, Union[str, List[str]]] = {},
        headers: Optional[RawHeaders] = None,
    ) -> Any:
        """
        Args:
            uri: uri to query
            args: parameters to be url-encoded in the body
            headers: a map from header name to a list of values for that header

        Returns:
            parsed json

        Raises:
            RequestTimedOutError: if there is a timeout before the response headers
               are received. Note there is currently no timeout on reading the response
               body.

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
            b"Accept": [b"application/json"],
        }
        if headers:
            actual_headers.update(headers)

        response = await self.request(
            "POST", uri, headers=Headers(actual_headers), data=query_bytes
        )

        body = await make_deferred_yieldable(readBody(response))

        if 200 <= response.code < 300:
            return json_decoder.decode(body.decode("utf-8"))
        else:
            raise HttpResponseException(
                response.code, response.phrase.decode("ascii", errors="replace"), body
            )

    async def post_json_get_json(
        self, uri: str, post_json: Any, headers: Optional[RawHeaders] = None
    ) -> Any:
        """

        Args:
            uri: URI to query.
            post_json: request body, to be encoded as json
            headers: a map from header name to a list of values for that header

        Returns:
            parsed json

        Raises:
            RequestTimedOutError: if there is a timeout before the response headers
               are received. Note there is currently no timeout on reading the response
               body.

            HttpResponseException: On a non-2xx HTTP response.

            ValueError: if the response was not JSON
        """
        json_str = encode_canonical_json(post_json)

        logger.debug("HTTP POST %s -> %s", json_str, uri)

        actual_headers = {
            b"Content-Type": [b"application/json"],
            b"User-Agent": [self.user_agent],
            b"Accept": [b"application/json"],
        }
        if headers:
            actual_headers.update(headers)

        response = await self.request(
            "POST", uri, headers=Headers(actual_headers), data=json_str
        )

        body = await make_deferred_yieldable(readBody(response))

        if 200 <= response.code < 300:
            return json_decoder.decode(body.decode("utf-8"))
        else:
            raise HttpResponseException(
                response.code, response.phrase.decode("ascii", errors="replace"), body
            )

    async def get_json(
        self, uri: str, args: QueryParams = {}, headers: Optional[RawHeaders] = None,
    ) -> Any:
        """Gets some json from the given URI.

        Args:
            uri: The URI to request, not including query parameters
            args: A dictionary used to create query string
            headers: a map from header name to a list of values for that header
        Returns:
            Succeeds when we get a 2xx HTTP response, with the HTTP body as JSON.
        Raises:
            RequestTimedOutError: if there is a timeout before the response headers
               are received. Note there is currently no timeout on reading the response
               body.

            HttpResponseException On a non-2xx HTTP response.

            ValueError: if the response was not JSON
        """
        actual_headers = {b"Accept": [b"application/json"]}
        if headers:
            actual_headers.update(headers)

        body = await self.get_raw(uri, args, headers=headers)
        return json_decoder.decode(body.decode("utf-8"))

    async def put_json(
        self,
        uri: str,
        json_body: Any,
        args: QueryParams = {},
        headers: RawHeaders = None,
    ) -> Any:
        """Puts some json to the given URI.

        Args:
            uri: The URI to request, not including query parameters
            json_body: The JSON to put in the HTTP body,
            args: A dictionary used to create query strings
            headers: a map from header name to a list of values for that header
        Returns:
            Succeeds when we get a 2xx HTTP response, with the HTTP body as JSON.
        Raises:
             RequestTimedOutError: if there is a timeout before the response headers
               are received. Note there is currently no timeout on reading the response
               body.

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
            b"Accept": [b"application/json"],
        }
        if headers:
            actual_headers.update(headers)

        response = await self.request(
            "PUT", uri, headers=Headers(actual_headers), data=json_str
        )

        body = await make_deferred_yieldable(readBody(response))

        if 200 <= response.code < 300:
            return json_decoder.decode(body.decode("utf-8"))
        else:
            raise HttpResponseException(
                response.code, response.phrase.decode("ascii", errors="replace"), body
            )

    async def get_raw(
        self, uri: str, args: QueryParams = {}, headers: Optional[RawHeaders] = None
    ) -> bytes:
        """Gets raw text from the given URI.

        Args:
            uri: The URI to request, not including query parameters
            args: A dictionary used to create query strings
            headers: a map from header name to a list of values for that header
        Returns:
            Succeeds when we get a 2xx HTTP response, with the
            HTTP body as bytes.
        Raises:
            RequestTimedOutError: if there is a timeout before the response headers
               are received. Note there is currently no timeout on reading the response
               body.

            HttpResponseException on a non-2xx HTTP response.
        """
        if len(args):
            query_bytes = urllib.parse.urlencode(args, True)
            uri = "%s?%s" % (uri, query_bytes)

        actual_headers = {b"User-Agent": [self.user_agent]}
        if headers:
            actual_headers.update(headers)

        response = await self.request("GET", uri, headers=Headers(actual_headers))

        body = await make_deferred_yieldable(readBody(response))

        if 200 <= response.code < 300:
            return body
        else:
            raise HttpResponseException(
                response.code, response.phrase.decode("ascii", errors="replace"), body
            )

    # XXX: FIXME: This is horribly copy-pasted from matrixfederationclient.
    # The two should be factored out.

    async def get_file(
        self,
        url: str,
        output_stream: BinaryIO,
        max_size: Optional[int] = None,
        headers: Optional[RawHeaders] = None,
    ) -> Tuple[int, Dict[bytes, List[bytes]], str, int]:
        """GETs a file from a given URL
        Args:
            url: The URL to GET
            output_stream: File to write the response body to.
            headers: A map from header name to a list of values for that header
        Returns:
            A tuple of the file length, dict of the response
            headers, absolute URI of the response and HTTP response code.

        Raises:
            RequestTimedOutError: if there is a timeout before the response headers
               are received. Note there is currently no timeout on reading the response
               body.

            SynapseError: if the response is not a 2xx, the remote file is too large, or
               another exception happens during the download.
        """

        actual_headers = {b"User-Agent": [self.user_agent]}
        if headers:
            actual_headers.update(headers)

        response = await self.request("GET", url, headers=Headers(actual_headers))

        resp_headers = dict(response.headers.getAllRawHeaders())

        if (
            b"Content-Length" in resp_headers
            and int(resp_headers[b"Content-Length"][0]) > max_size
        ):
            logger.warning("Requested URL is too large > %r bytes" % (self.max_size,))
            raise SynapseError(
                502,
                "Requested file is too large > %r bytes" % (self.max_size,),
                Codes.TOO_LARGE,
            )

        if response.code > 299:
            logger.warning("Got %d when downloading %s" % (response.code, url))
            raise SynapseError(502, "Got error %d" % (response.code,), Codes.UNKNOWN)

        # TODO: if our Content-Type is HTML or something, just read the first
        # N bytes into RAM rather than saving it all to disk only to read it
        # straight back in again

        try:
            length = await make_deferred_yieldable(
                _readBodyToFile(response, output_stream, max_size)
            )
        except SynapseError:
            # This can happen e.g. because the body is too large.
            raise
        except Exception as e:
            raise SynapseError(502, ("Failed to download remote body: %s" % e)) from e

        return (
            length,
            resp_headers,
            response.request.absoluteURI.decode("ascii"),
            response.code,
        )


def _timeout_to_request_timed_out_error(f: Failure):
    if f.check(twisted_error.TimeoutError, twisted_error.ConnectingCancelledError):
        # The TCP connection has its own timeout (set by the 'connectTimeout' param
        # on the Agent), which raises twisted_error.TimeoutError exception.
        raise RequestTimedOutError("Timeout connecting to remote server")
    elif f.check(defer.TimeoutError, ResponseNeverReceived):
        # this one means that we hit our overall timeout on the request
        raise RequestTimedOutError("Timeout waiting for response from remote server")

    return f


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


def encode_urlencode_args(args):
    return {k: encode_urlencode_arg(v) for k, v in args.items()}


def encode_urlencode_arg(arg):
    if isinstance(arg, str):
        return arg.encode("utf-8")
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
