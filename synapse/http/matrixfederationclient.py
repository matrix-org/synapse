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
import cgi
import logging
import random
import sys

from six import PY3, string_types
from six.moves import urllib

import treq
from canonicaljson import encode_canonical_json
from prometheus_client import Counter
from signedjson.sign import sign_json

from twisted.internet import defer, protocol
from twisted.internet.error import DNSLookupError
from twisted.web._newclient import ResponseDone
from twisted.web.client import Agent, HTTPConnectionPool
from twisted.web.http_headers import Headers

import synapse.metrics
import synapse.util.retryutils
from synapse.api.errors import (
    Codes,
    FederationDeniedError,
    HttpResponseException,
    SynapseError,
)
from synapse.http.endpoint import matrix_federation_endpoint
from synapse.util import logcontext
from synapse.util.async_helpers import timeout_no_seriously
from synapse.util.logcontext import make_deferred_yieldable
from synapse.util.metrics import Measure

logger = logging.getLogger(__name__)
outbound_logger = logging.getLogger("synapse.http.outbound")

outgoing_requests_counter = Counter("synapse_http_matrixfederationclient_requests",
                                    "", ["method"])
incoming_responses_counter = Counter("synapse_http_matrixfederationclient_responses",
                                     "", ["method", "code"])


MAX_LONG_RETRIES = 10
MAX_SHORT_RETRIES = 3

if PY3:
    MAXINT = sys.maxsize
else:
    MAXINT = sys.maxint


class MatrixFederationEndpointFactory(object):
    def __init__(self, hs):
        self.reactor = hs.get_reactor()
        self.tls_client_options_factory = hs.tls_client_options_factory

    def endpointForURI(self, uri):
        destination = uri.netloc.decode('ascii')

        return matrix_federation_endpoint(
            self.reactor, destination, timeout=10,
            tls_client_options_factory=self.tls_client_options_factory
        )


class MatrixFederationHttpClient(object):
    """HTTP client used to talk to other homeservers over the federation
    protocol. Send client certificates and signs requests.

    Attributes:
        agent (twisted.web.client.Agent): The twisted Agent used to send the
            requests.
    """

    def __init__(self, hs):
        self.hs = hs
        self.signing_key = hs.config.signing_key[0]
        self.server_name = hs.hostname
        reactor = hs.get_reactor()
        pool = HTTPConnectionPool(reactor)
        pool.retryAutomatically = False
        pool.maxPersistentPerHost = 5
        pool.cachedConnectionTimeout = 2 * 60
        self.agent = Agent.usingEndpointFactory(
            reactor, MatrixFederationEndpointFactory(hs), pool=pool
        )
        self.clock = hs.get_clock()
        self._store = hs.get_datastore()
        self.version_string = hs.version_string.encode('ascii')
        self._next_id = 1
        self.default_timeout = 60

    def _create_url(self, destination, path_bytes, param_bytes, query_bytes):
        return urllib.parse.urlunparse(
            (b"matrix", destination, path_bytes, param_bytes, query_bytes, b"")
        )

    @defer.inlineCallbacks
    def _request(self, destination, method, path,
                 json=None, json_callback=None,
                 param_bytes=b"",
                 query=None, retry_on_dns_fail=True,
                 timeout=None, long_retries=False,
                 ignore_backoff=False,
                 backoff_on_404=False):
        """
        Creates and sends a request to the given server.

        Args:
            destination (str): The remote server to send the HTTP request to.
            method (str): HTTP method
            path (str): The HTTP path
            json (dict or None): JSON to send in the body.
            json_callback (func or None): A callback to generate the JSON.
            query (dict or None): Query arguments.
            ignore_backoff (bool): true to ignore the historical backoff data
                and try the request anyway.
            backoff_on_404 (bool): Back off if we get a 404

        Returns:
            Deferred: resolves with the http response object on success.

            Fails with ``HTTPRequestException``: if we get an HTTP response
                code >= 300.

            Fails with ``NotRetryingDestination`` if we are not yet ready
                to retry this server.

            Fails with ``FederationDeniedError`` if this destination
                is not on our federation whitelist

            (May also fail with plenty of other Exceptions for things like DNS
                failures, connection failures, SSL failures.)
        """
        if timeout:
            _sec_timeout = timeout / 1000
        else:
            _sec_timeout = self.default_timeout

        if (
            self.hs.config.federation_domain_whitelist is not None and
            destination not in self.hs.config.federation_domain_whitelist
        ):
            raise FederationDeniedError(destination)

        limiter = yield synapse.util.retryutils.get_retry_limiter(
            destination,
            self.clock,
            self._store,
            backoff_on_404=backoff_on_404,
            ignore_backoff=ignore_backoff,
        )

        headers_dict = {}
        path_bytes = path.encode("ascii")
        if query:
            query_bytes = encode_query_args(query)
        else:
            query_bytes = b""

        headers_dict = {
            "User-Agent": [self.version_string],
            "Host": [destination],
        }

        with limiter:
            url = self._create_url(
                destination.encode("ascii"), path_bytes, param_bytes, query_bytes
            ).decode('ascii')

            txn_id = "%s-O-%s" % (method, self._next_id)
            self._next_id = (self._next_id + 1) % (MAXINT - 1)

            # XXX: Would be much nicer to retry only at the transaction-layer
            # (once we have reliable transactions in place)
            if long_retries:
                retries_left = MAX_LONG_RETRIES
            else:
                retries_left = MAX_SHORT_RETRIES

            http_url = urllib.parse.urlunparse(
                (b"", b"", path_bytes, param_bytes, query_bytes, b"")
            ).decode('ascii')

            log_result = None
            while True:
                try:
                    if json_callback:
                        json = json_callback()

                    if json:
                        data = encode_canonical_json(json)
                        headers_dict["Content-Type"] = ["application/json"]
                        self.sign_request(
                            destination, method, http_url, headers_dict, json
                        )
                    else:
                        data = None
                        self.sign_request(destination, method, http_url, headers_dict)

                    outbound_logger.info(
                        "{%s} [%s] Sending request: %s %s",
                        txn_id, destination, method, url
                    )

                    request_deferred = treq.request(
                        method,
                        url,
                        headers=Headers(headers_dict),
                        data=data,
                        agent=self.agent,
                        reactor=self.hs.get_reactor(),
                        unbuffered=True
                    )
                    request_deferred.addTimeout(_sec_timeout, self.hs.get_reactor())

                    # Sometimes the timeout above doesn't work, so lets hack yet
                    # another layer of timeouts in in the vain hope that at some
                    # point the world made sense and this really really really
                    # should work.
                    request_deferred = timeout_no_seriously(
                        request_deferred,
                        timeout=_sec_timeout * 2,
                        reactor=self.hs.get_reactor(),
                    )

                    with Measure(self.clock, "outbound_request"):
                        response = yield make_deferred_yieldable(
                            request_deferred,
                        )

                    log_result = "%d %s" % (response.code, response.phrase,)
                    break
                except Exception as e:
                    if not retry_on_dns_fail and isinstance(e, DNSLookupError):
                        logger.warn(
                            "DNS Lookup failed to %s with %s",
                            destination,
                            e
                        )
                        log_result = "DNS Lookup failed to %s with %s" % (
                            destination, e
                        )
                        raise

                    logger.warn(
                        "{%s} Sending request failed to %s: %s %s: %s",
                        txn_id,
                        destination,
                        method,
                        url,
                        _flatten_response_never_received(e),
                    )

                    log_result = _flatten_response_never_received(e)

                    if retries_left and not timeout:
                        if long_retries:
                            delay = 4 ** (MAX_LONG_RETRIES + 1 - retries_left)
                            delay = min(delay, 60)
                            delay *= random.uniform(0.8, 1.4)
                        else:
                            delay = 0.5 * 2 ** (MAX_SHORT_RETRIES - retries_left)
                            delay = min(delay, 2)
                            delay *= random.uniform(0.8, 1.4)

                        logger.debug(
                            "{%s} Waiting %s before sending to %s...",
                            txn_id,
                            delay,
                            destination
                        )

                        yield self.clock.sleep(delay)
                        retries_left -= 1
                    else:
                        raise
                finally:
                    outbound_logger.info(
                        "{%s} [%s] Result: %s",
                        txn_id,
                        destination,
                        log_result,
                    )

            if 200 <= response.code < 300:
                pass
            else:
                # :'(
                # Update transactions table?
                with logcontext.PreserveLoggingContext():
                    d = treq.content(response)
                    d.addTimeout(_sec_timeout, self.hs.get_reactor())
                    body = yield make_deferred_yieldable(d)
                raise HttpResponseException(
                    response.code, response.phrase, body
                )

            defer.returnValue(response)

    def sign_request(self, destination, method, url_bytes, headers_dict,
                     content=None, destination_is=None):
        """
        Signs a request by adding an Authorization header to headers_dict
        Args:
            destination (bytes|None): The desination home server of the request.
                May be None if the destination is an identity server, in which case
                destination_is must be non-None.
            method (bytes): The HTTP method of the request
            url_bytes (bytes): The URI path of the request
            headers_dict (dict): Dictionary of request headers to append to
            content (bytes): The body of the request
            destination_is (bytes): As 'destination', but if the destination is an
                identity server

        Returns:
            None
        """
        request = {
            "method": method,
            "uri": url_bytes,
            "origin": self.server_name,
        }

        if destination is not None:
            request["destination"] = destination

        if destination_is is not None:
            request["destination_is"] = destination_is

        if content is not None:
            request["content"] = content

        request = sign_json(request, self.server_name, self.signing_key)

        auth_headers = []

        for key, sig in request["signatures"][self.server_name].items():
            auth_headers.append((
                "X-Matrix origin=%s,key=\"%s\",sig=\"%s\"" % (
                    self.server_name, key, sig,
                )).encode('ascii')
            )

        headers_dict[b"Authorization"] = auth_headers

    @defer.inlineCallbacks
    def put_json(self, destination, path, args={}, data={},
                 json_data_callback=None,
                 long_retries=False, timeout=None,
                 ignore_backoff=False,
                 backoff_on_404=False):
        """ Sends the specifed json data using PUT

        Args:
            destination (str): The remote server to send the HTTP request
                to.
            path (str): The HTTP path.
            args (dict): query params
            data (dict): A dict containing the data that will be used as
                the request body. This will be encoded as JSON.
            json_data_callback (callable): A callable returning the dict to
                use as the request body.
            long_retries (bool): A boolean that indicates whether we should
                retry for a short or long time.
            timeout(int): How long to try (in ms) the destination for before
                giving up. None indicates no timeout.
            ignore_backoff (bool): true to ignore the historical backoff data
                and try the request anyway.
            backoff_on_404 (bool): True if we should count a 404 response as
                a failure of the server (and should therefore back off future
                requests)

        Returns:
            Deferred: Succeeds when we get a 2xx HTTP response. The result
            will be the decoded JSON body.

            Fails with ``HTTPRequestException`` if we get an HTTP response
            code >= 300.

            Fails with ``NotRetryingDestination`` if we are not yet ready
            to retry this server.

            Fails with ``FederationDeniedError`` if this destination
            is not on our federation whitelist
        """

        if not json_data_callback:
            json_data_callback = lambda: data

        response = yield self._request(
            destination,
            "PUT",
            path,
            json_callback=json_data_callback,
            query=args,
            long_retries=long_retries,
            timeout=timeout,
            ignore_backoff=ignore_backoff,
            backoff_on_404=backoff_on_404,
        )

        if 200 <= response.code < 300:
            # We need to update the transactions table to say it was sent?
            check_content_type_is_json(response.headers)

        with logcontext.PreserveLoggingContext():
            d = treq.json_content(response)
            d.addTimeout(self.default_timeout, self.hs.get_reactor())
            body = yield make_deferred_yieldable(d)
        defer.returnValue(body)

    @defer.inlineCallbacks
    def post_json(self, destination, path, data={}, long_retries=False,
                  timeout=None, ignore_backoff=False, args={}):
        """ Sends the specifed json data using POST

        Args:
            destination (str): The remote server to send the HTTP request
                to.
            path (str): The HTTP path.
            data (dict): A dict containing the data that will be used as
                the request body. This will be encoded as JSON.
            long_retries (bool): A boolean that indicates whether we should
                retry for a short or long time.
            timeout(int): How long to try (in ms) the destination for before
                giving up. None indicates no timeout.
            ignore_backoff (bool): true to ignore the historical backoff data and
                try the request anyway.
            args (dict): query params
        Returns:
            Deferred: Succeeds when we get a 2xx HTTP response. The result
            will be the decoded JSON body.

            Fails with ``HTTPRequestException`` if we get an HTTP response
            code >= 300.

            Fails with ``NotRetryingDestination`` if we are not yet ready
            to retry this server.

            Fails with ``FederationDeniedError`` if this destination
            is not on our federation whitelist
        """
        response = yield self._request(
            destination,
            "POST",
            path,
            query=args,
            json=data,
            long_retries=long_retries,
            timeout=timeout,
            ignore_backoff=ignore_backoff,
        )

        if 200 <= response.code < 300:
            # We need to update the transactions table to say it was sent?
            check_content_type_is_json(response.headers)

        with logcontext.PreserveLoggingContext():
            d = treq.json_content(response)
            if timeout:
                _sec_timeout = timeout / 1000
            else:
                _sec_timeout = self.default_timeout

            d.addTimeout(_sec_timeout, self.hs.get_reactor())
            body = yield make_deferred_yieldable(d)

        defer.returnValue(body)

    @defer.inlineCallbacks
    def get_json(self, destination, path, args=None, retry_on_dns_fail=True,
                 timeout=None, ignore_backoff=False):
        """ GETs some json from the given host homeserver and path

        Args:
            destination (str): The remote server to send the HTTP request
                to.
            path (str): The HTTP path.
            args (dict|None): A dictionary used to create query strings, defaults to
                None.
            timeout (int): How long to try (in ms) the destination for before
                giving up. None indicates no timeout and that the request will
                be retried.
            ignore_backoff (bool): true to ignore the historical backoff data
                and try the request anyway.
        Returns:
            Deferred: Succeeds when we get a 2xx HTTP response. The result
            will be the decoded JSON body.

            Fails with ``HTTPRequestException`` if we get an HTTP response
            code >= 300.

            Fails with ``NotRetryingDestination`` if we are not yet ready
            to retry this server.

            Fails with ``FederationDeniedError`` if this destination
            is not on our federation whitelist
        """
        logger.debug("get_json args: %s", args)

        logger.debug("Query bytes: %s Retry DNS: %s", args, retry_on_dns_fail)

        response = yield self._request(
            destination,
            "GET",
            path,
            query=args,
            retry_on_dns_fail=retry_on_dns_fail,
            timeout=timeout,
            ignore_backoff=ignore_backoff,
        )

        if 200 <= response.code < 300:
            # We need to update the transactions table to say it was sent?
            check_content_type_is_json(response.headers)

        with logcontext.PreserveLoggingContext():
            d = treq.json_content(response)
            d.addTimeout(self.default_timeout, self.hs.get_reactor())
            body = yield make_deferred_yieldable(d)

        defer.returnValue(body)

    @defer.inlineCallbacks
    def delete_json(self, destination, path, long_retries=False,
                    timeout=None, ignore_backoff=False, args={}):
        """Send a DELETE request to the remote expecting some json response

        Args:
            destination (str): The remote server to send the HTTP request
                to.
            path (str): The HTTP path.
            long_retries (bool): A boolean that indicates whether we should
                retry for a short or long time.
            timeout(int): How long to try (in ms) the destination for before
                giving up. None indicates no timeout.
            ignore_backoff (bool): true to ignore the historical backoff data and
                try the request anyway.
        Returns:
            Deferred: Succeeds when we get a 2xx HTTP response. The result
            will be the decoded JSON body.

            Fails with ``HTTPRequestException`` if we get an HTTP response
            code >= 300.

            Fails with ``NotRetryingDestination`` if we are not yet ready
            to retry this server.

            Fails with ``FederationDeniedError`` if this destination
            is not on our federation whitelist
        """
        response = yield self._request(
            destination,
            "DELETE",
            path,
            query=args,
            long_retries=long_retries,
            timeout=timeout,
            ignore_backoff=ignore_backoff,
        )

        if 200 <= response.code < 300:
            # We need to update the transactions table to say it was sent?
            check_content_type_is_json(response.headers)

        with logcontext.PreserveLoggingContext():
            d = treq.json_content(response)
            d.addTimeout(self.default_timeout, self.hs.get_reactor())
            body = yield make_deferred_yieldable(d)

        defer.returnValue(body)

    @defer.inlineCallbacks
    def get_file(self, destination, path, output_stream, args={},
                 retry_on_dns_fail=True, max_size=None,
                 ignore_backoff=False):
        """GETs a file from a given homeserver
        Args:
            destination (str): The remote server to send the HTTP request to.
            path (str): The HTTP path to GET.
            output_stream (file): File to write the response body to.
            args (dict): Optional dictionary used to create the query string.
            ignore_backoff (bool): true to ignore the historical backoff data
                and try the request anyway.
        Returns:
            Deferred: resolves with an (int,dict) tuple of the file length and
            a dict of the response headers.

            Fails with ``HTTPRequestException`` if we get an HTTP response code
            >= 300

            Fails with ``NotRetryingDestination`` if we are not yet ready
            to retry this server.

            Fails with ``FederationDeniedError`` if this destination
            is not on our federation whitelist
        """
        response = yield self._request(
            destination,
            "GET",
            path,
            query=args,
            retry_on_dns_fail=retry_on_dns_fail,
            ignore_backoff=ignore_backoff,
        )

        headers = dict(response.headers.getAllRawHeaders())

        try:
            with logcontext.PreserveLoggingContext():
                d = _readBodyToFile(response, output_stream, max_size)
                d.addTimeout(self.default_timeout, self.hs.get_reactor())
                length = yield make_deferred_yieldable(d)
        except Exception:
            logger.exception("Failed to download body")
            raise

        defer.returnValue((length, headers))


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
        else:
            self.deferred.errback(reason)


def _readBodyToFile(response, stream, max_size):
    d = defer.Deferred()
    response.deliverBody(_ReadBodyToFileProtocol(stream, d, max_size))
    return d


def _flatten_response_never_received(e):
    if hasattr(e, "reasons"):
        reasons = ", ".join(
            _flatten_response_never_received(f.value)
            for f in e.reasons
        )

        return "%s:[%s]" % (type(e).__name__, reasons)
    else:
        return repr(e)


def check_content_type_is_json(headers):
    """
    Check that a set of HTTP headers have a Content-Type header, and that it
    is application/json.

    Args:
        headers (twisted.web.http_headers.Headers): headers to check

    Raises:
        RuntimeError if the

    """
    c_type = headers.getRawHeaders(b"Content-Type")
    if c_type is None:
        raise RuntimeError(
            "No Content-Type header"
        )

    c_type = c_type[0].decode('ascii')  # only the first header
    val, options = cgi.parse_header(c_type)
    if val != "application/json":
        raise RuntimeError(
            "Content-Type not application/json: was '%s'" % c_type
        )


def encode_query_args(args):
    if args is None:
        return b""

    encoded_args = {}
    for k, vs in args.items():
        if isinstance(vs, string_types):
            vs = [vs]
        encoded_args[k] = [v.encode("UTF-8") for v in vs]

    query_bytes = urllib.parse.urlencode(encoded_args, True)

    return query_bytes.encode('utf8')
