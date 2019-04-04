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
from io import BytesIO

from six import PY3, raise_from, string_types
from six.moves import urllib

import attr
import treq
from canonicaljson import encode_canonical_json
from prometheus_client import Counter
from signedjson.sign import sign_json

from twisted.internet import defer, protocol
from twisted.internet.error import DNSLookupError
from twisted.internet.task import _EPSILON, Cooperator
from twisted.web._newclient import ResponseDone
from twisted.web.http_headers import Headers

import synapse.metrics
import synapse.util.retryutils
from synapse.api.errors import (
    Codes,
    FederationDeniedError,
    HttpResponseException,
    RequestSendFailed,
    SynapseError,
)
from synapse.http import QuieterFileBodyProducer
from synapse.http.federation.matrix_federation_agent import MatrixFederationAgent
from synapse.util.async_helpers import timeout_deferred
from synapse.util.logcontext import make_deferred_yieldable
from synapse.util.metrics import Measure

logger = logging.getLogger(__name__)

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


_next_id = 1


@attr.s
class MatrixFederationRequest(object):
    method = attr.ib()
    """HTTP method
    :type: str
    """

    path = attr.ib()
    """HTTP path
    :type: str
    """

    destination = attr.ib()
    """The remote server to send the HTTP request to.
    :type: str"""

    json = attr.ib(default=None)
    """JSON to send in the body.
    :type: dict|None
    """

    json_callback = attr.ib(default=None)
    """A callback to generate the JSON.
    :type: func|None
    """

    query = attr.ib(default=None)
    """Query arguments.
    :type: dict|None
    """

    txn_id = attr.ib(default=None)
    """Unique ID for this request (for logging)
    :type: str|None
    """

    def __attrs_post_init__(self):
        global _next_id
        self.txn_id = "%s-O-%s" % (self.method, _next_id)
        _next_id = (_next_id + 1) % (MAXINT - 1)

    def get_json(self):
        if self.json_callback:
            return self.json_callback()
        return self.json


@defer.inlineCallbacks
def _handle_json_response(reactor, timeout_sec, request, response):
    """
    Reads the JSON body of a response, with a timeout

    Args:
        reactor (IReactor): twisted reactor, for the timeout
        timeout_sec (float): number of seconds to wait for response to complete
        request (MatrixFederationRequest): the request that triggered the response
        response (IResponse): response to the request

    Returns:
        dict: parsed JSON response
    """
    try:
        check_content_type_is_json(response.headers)

        d = treq.json_content(response)
        d = timeout_deferred(
            d,
            timeout=timeout_sec,
            reactor=reactor,
        )

        body = yield make_deferred_yieldable(d)
    except Exception as e:
        logger.warn(
            "{%s} [%s] Error reading response: %s",
            request.txn_id,
            request.destination,
            e,
        )
        raise
    logger.info(
        "{%s} [%s] Completed: %d %s",
        request.txn_id,
        request.destination,
        response.code,
        response.phrase.decode('ascii', errors='replace'),
    )
    defer.returnValue(body)


class MatrixFederationHttpClient(object):
    """HTTP client used to talk to other homeservers over the federation
    protocol. Send client certificates and signs requests.

    Attributes:
        agent (twisted.web.client.Agent): The twisted Agent used to send the
            requests.
    """

    def __init__(self, hs, tls_client_options_factory):
        self.hs = hs
        self.signing_key = hs.config.signing_key[0]
        self.server_name = hs.hostname
        reactor = hs.get_reactor()

        self.agent = MatrixFederationAgent(
            hs.get_reactor(),
            tls_client_options_factory,
        )
        self.clock = hs.get_clock()
        self._store = hs.get_datastore()
        self.version_string_bytes = hs.version_string.encode('ascii')
        self.default_timeout = 60

        def schedule(x):
            reactor.callLater(_EPSILON, x)

        self._cooperator = Cooperator(scheduler=schedule)

    @defer.inlineCallbacks
    def _send_request_with_optional_trailing_slash(
        self,
        request,
        try_trailing_slash_on_400=False,
        **send_request_args
    ):
        """Wrapper for _send_request which can optionally retry the request
        upon receiving a combination of a 400 HTTP response code and a
        'M_UNRECOGNIZED' errcode. This is a workaround for Synapse <= v0.99.3
        due to #3622.

        Args:
            request (MatrixFederationRequest): details of request to be sent
            try_trailing_slash_on_400 (bool): Whether on receiving a 400
                'M_UNRECOGNIZED' from the server to retry the request with a
                trailing slash appended to the request path.
            send_request_args (Dict): A dictionary of arguments to pass to
                `_send_request()`.

        Raises:
            HttpResponseException: If we get an HTTP response code >= 300
                (except 429).

        Returns:
            Deferred[Dict]: Parsed JSON response body.
        """
        try:
            response = yield self._send_request(
                request, **send_request_args
            )
        except HttpResponseException as e:
            # Received an HTTP error > 300. Check if it meets the requirements
            # to retry with a trailing slash
            if not try_trailing_slash_on_400:
                raise

            if e.code != 400 or e.to_synapse_error().errcode != "M_UNRECOGNIZED":
                raise

            # Retry with a trailing slash if we received a 400 with
            # 'M_UNRECOGNIZED' which some endpoints can return when omitting a
            # trailing slash on Synapse <= v0.99.3.
            logger.info("Retrying request with trailing slash")
            request.path += "/"

            response = yield self._send_request(
                request, **send_request_args
            )

        defer.returnValue(response)

    @defer.inlineCallbacks
    def _send_request(
        self,
        request,
        retry_on_dns_fail=True,
        timeout=None,
        long_retries=False,
        ignore_backoff=False,
        backoff_on_404=False,
    ):
        """
        Sends a request to the given server.

        Args:
            request (MatrixFederationRequest): details of request to be sent

            timeout (int|None): number of milliseconds to wait for the response headers
                (including connecting to the server). 60s by default.

            ignore_backoff (bool): true to ignore the historical backoff data
                and try the request anyway.

            backoff_on_404 (bool): Back off if we get a 404

        Returns:
            Deferred[twisted.web.client.Response]: resolves with the HTTP
            response object on success.

        Raises:
            HttpResponseException: If we get an HTTP response code >= 300
                (except 429).
            NotRetryingDestination: If we are not yet ready to retry this
                server.
            FederationDeniedError: If this destination  is not on our
                federation whitelist
            RequestSendFailed: If there were problems connecting to the
                remote, due to e.g. DNS failures, connection timeouts etc.
        """
        if timeout:
            _sec_timeout = timeout / 1000
        else:
            _sec_timeout = self.default_timeout

        if (
            self.hs.config.federation_domain_whitelist is not None and
            request.destination not in self.hs.config.federation_domain_whitelist
        ):
            raise FederationDeniedError(request.destination)

        limiter = yield synapse.util.retryutils.get_retry_limiter(
            request.destination,
            self.clock,
            self._store,
            backoff_on_404=backoff_on_404,
            ignore_backoff=ignore_backoff,
        )

        method_bytes = request.method.encode("ascii")
        destination_bytes = request.destination.encode("ascii")
        path_bytes = request.path.encode("ascii")
        if request.query:
            query_bytes = encode_query_args(request.query)
        else:
            query_bytes = b""

        headers_dict = {
            b"User-Agent": [self.version_string_bytes],
        }

        with limiter:
            # XXX: Would be much nicer to retry only at the transaction-layer
            # (once we have reliable transactions in place)
            if long_retries:
                retries_left = MAX_LONG_RETRIES
            else:
                retries_left = MAX_SHORT_RETRIES

            url_bytes = urllib.parse.urlunparse((
                b"matrix", destination_bytes,
                path_bytes, None, query_bytes, b"",
            ))
            url_str = url_bytes.decode('ascii')

            url_to_sign_bytes = urllib.parse.urlunparse((
                b"", b"",
                path_bytes, None, query_bytes, b"",
            ))

            while True:
                try:
                    json = request.get_json()
                    if json:
                        headers_dict[b"Content-Type"] = [b"application/json"]
                        auth_headers = self.build_auth_headers(
                            destination_bytes, method_bytes, url_to_sign_bytes,
                            json,
                        )
                        data = encode_canonical_json(json)
                        producer = QuieterFileBodyProducer(
                            BytesIO(data),
                            cooperator=self._cooperator,
                        )
                    else:
                        producer = None
                        auth_headers = self.build_auth_headers(
                            destination_bytes, method_bytes, url_to_sign_bytes,
                        )

                    headers_dict[b"Authorization"] = auth_headers

                    logger.info(
                        "{%s} [%s] Sending request: %s %s; timeout %fs",
                        request.txn_id, request.destination, request.method,
                        url_str, _sec_timeout,
                    )

                    try:
                        with Measure(self.clock, "outbound_request"):
                            # we don't want all the fancy cookie and redirect handling
                            # that treq.request gives: just use the raw Agent.
                            request_deferred = self.agent.request(
                                method_bytes,
                                url_bytes,
                                headers=Headers(headers_dict),
                                bodyProducer=producer,
                            )

                            request_deferred = timeout_deferred(
                                request_deferred,
                                timeout=_sec_timeout,
                                reactor=self.hs.get_reactor(),
                            )

                            response = yield request_deferred
                    except DNSLookupError as e:
                        raise_from(RequestSendFailed(e, can_retry=retry_on_dns_fail), e)
                    except Exception as e:
                        logger.info("Failed to send request: %s", e)
                        raise_from(RequestSendFailed(e, can_retry=True), e)

                    logger.info(
                        "{%s} [%s] Got response headers: %d %s",
                        request.txn_id,
                        request.destination,
                        response.code,
                        response.phrase.decode('ascii', errors='replace'),
                    )

                    if 200 <= response.code < 300:
                        pass
                    else:
                        # :'(
                        # Update transactions table?
                        d = treq.content(response)
                        d = timeout_deferred(
                            d,
                            timeout=_sec_timeout,
                            reactor=self.hs.get_reactor(),
                        )

                        try:
                            body = yield make_deferred_yieldable(d)
                        except Exception as e:
                            # Eh, we're already going to raise an exception so lets
                            # ignore if this fails.
                            logger.warn(
                                "{%s} [%s] Failed to get error response: %s %s: %s",
                                request.txn_id,
                                request.destination,
                                request.method,
                                url_str,
                                _flatten_response_never_received(e),
                            )
                            body = None

                        e = HttpResponseException(
                            response.code, response.phrase, body
                        )

                        # Retry if the error is a 429 (Too Many Requests),
                        # otherwise just raise a standard HttpResponseException
                        if response.code == 429:
                            raise_from(RequestSendFailed(e, can_retry=True), e)
                        else:
                            raise e

                    break
                except RequestSendFailed as e:
                    logger.warn(
                        "{%s} [%s] Request failed: %s %s: %s",
                        request.txn_id,
                        request.destination,
                        request.method,
                        url_str,
                        _flatten_response_never_received(e.inner_exception),
                    )

                    if not e.can_retry:
                        raise

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
                            "{%s} [%s] Waiting %ss before re-sending...",
                            request.txn_id,
                            request.destination,
                            delay,
                        )

                        yield self.clock.sleep(delay)
                        retries_left -= 1
                    else:
                        raise

                except Exception as e:
                    logger.warn(
                        "{%s} [%s] Request failed: %s %s: %s",
                        request.txn_id,
                        request.destination,
                        request.method,
                        url_str,
                        _flatten_response_never_received(e),
                    )
                    raise

            defer.returnValue(response)

    def build_auth_headers(
        self, destination, method, url_bytes, content=None, destination_is=None,
    ):
        """
        Builds the Authorization headers for a federation request
        Args:
            destination (bytes|None): The desination home server of the request.
                May be None if the destination is an identity server, in which case
                destination_is must be non-None.
            method (bytes): The HTTP method of the request
            url_bytes (bytes): The URI path of the request
            content (object): The body of the request
            destination_is (bytes): As 'destination', but if the destination is an
                identity server

        Returns:
            list[bytes]: a list of headers to be added as "Authorization:" headers
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
        return auth_headers

    @defer.inlineCallbacks
    def put_json(self, destination, path, args={}, data={},
                 json_data_callback=None,
                 long_retries=False, timeout=None,
                 ignore_backoff=False,
                 backoff_on_404=False,
                 try_trailing_slash_on_400=False):
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
                requests).
            try_trailing_slash_on_400 (bool): True if on a 400 M_UNRECOGNIZED
                response we should try appending a trailing slash to the end
                of the request. Workaround for #3622 in Synapse <= v0.99.3. This
                will be attempted before backing off if backing off has been
                enabled.

        Returns:
            Deferred[dict|list]: Succeeds when we get a 2xx HTTP response. The
            result will be the decoded JSON body.

        Raises:
            HttpResponseException: If we get an HTTP response code >= 300
                (except 429).
            NotRetryingDestination: If we are not yet ready to retry this
                server.
            FederationDeniedError: If this destination  is not on our
                federation whitelist
            RequestSendFailed: If there were problems connecting to the
                remote, due to e.g. DNS failures, connection timeouts etc.
        """
        request = MatrixFederationRequest(
            method="PUT",
            destination=destination,
            path=path,
            query=args,
            json_callback=json_data_callback,
            json=data,
        )

        response = yield self._send_request_with_optional_trailing_slash(
            request,
            try_trailing_slash_on_400,
            backoff_on_404=backoff_on_404,
            ignore_backoff=ignore_backoff,
            long_retries=long_retries,
            timeout=timeout,
        )

        body = yield _handle_json_response(
            self.hs.get_reactor(), self.default_timeout, request, response,
        )

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
            Deferred[dict|list]: Succeeds when we get a 2xx HTTP response. The
            result will be the decoded JSON body.

        Raises:
            HttpResponseException: If we get an HTTP response code >= 300
                (except 429).
            NotRetryingDestination: If we are not yet ready to retry this
                server.
            FederationDeniedError: If this destination  is not on our
                federation whitelist
            RequestSendFailed: If there were problems connecting to the
                remote, due to e.g. DNS failures, connection timeouts etc.
        """

        request = MatrixFederationRequest(
            method="POST",
            destination=destination,
            path=path,
            query=args,
            json=data,
        )

        response = yield self._send_request(
            request,
            long_retries=long_retries,
            timeout=timeout,
            ignore_backoff=ignore_backoff,
        )

        if timeout:
            _sec_timeout = timeout / 1000
        else:
            _sec_timeout = self.default_timeout

        body = yield _handle_json_response(
            self.hs.get_reactor(), _sec_timeout, request, response,
        )
        defer.returnValue(body)

    @defer.inlineCallbacks
    def get_json(self, destination, path, args=None, retry_on_dns_fail=True,
                 timeout=None, ignore_backoff=False,
                 try_trailing_slash_on_400=False):
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
            try_trailing_slash_on_400 (bool): True if on a 400 M_UNRECOGNIZED
                response we should try appending a trailing slash to the end of
                the request. Workaround for #3622 in Synapse <= v0.99.3.
        Returns:
            Deferred[dict|list]: Succeeds when we get a 2xx HTTP response. The
            result will be the decoded JSON body.

        Raises:
            HttpResponseException: If we get an HTTP response code >= 300
                (except 429).
            NotRetryingDestination: If we are not yet ready to retry this
                server.
            FederationDeniedError: If this destination  is not on our
                federation whitelist
            RequestSendFailed: If there were problems connecting to the
                remote, due to e.g. DNS failures, connection timeouts etc.
        """
        logger.debug("get_json args: %s", args)

        logger.debug("Query bytes: %s Retry DNS: %s", args, retry_on_dns_fail)

        request = MatrixFederationRequest(
            method="GET",
            destination=destination,
            path=path,
            query=args,
        )

        response = yield self._send_request_with_optional_trailing_slash(
            request,
            try_trailing_slash_on_400,
            backoff_on_404=False,
            ignore_backoff=ignore_backoff,
            retry_on_dns_fail=retry_on_dns_fail,
            timeout=timeout,
        )

        body = yield _handle_json_response(
            self.hs.get_reactor(), self.default_timeout, request, response,
        )

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
            Deferred[dict|list]: Succeeds when we get a 2xx HTTP response. The
            result will be the decoded JSON body.

        Raises:
            HttpResponseException: If we get an HTTP response code >= 300
                (except 429).
            NotRetryingDestination: If we are not yet ready to retry this
                server.
            FederationDeniedError: If this destination  is not on our
                federation whitelist
            RequestSendFailed: If there were problems connecting to the
                remote, due to e.g. DNS failures, connection timeouts etc.
        """
        request = MatrixFederationRequest(
            method="DELETE",
            destination=destination,
            path=path,
            query=args,
        )

        response = yield self._send_request(
            request,
            long_retries=long_retries,
            timeout=timeout,
            ignore_backoff=ignore_backoff,
        )

        body = yield _handle_json_response(
            self.hs.get_reactor(), self.default_timeout, request, response,
        )
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
            Deferred[tuple[int, dict]]: Resolves with an (int,dict) tuple of
            the file length and a dict of the response headers.

        Raises:
            HttpResponseException: If we get an HTTP response code >= 300
                (except 429).
            NotRetryingDestination: If we are not yet ready to retry this
                server.
            FederationDeniedError: If this destination  is not on our
                federation whitelist
            RequestSendFailed: If there were problems connecting to the
                remote, due to e.g. DNS failures, connection timeouts etc.
        """
        request = MatrixFederationRequest(
            method="GET",
            destination=destination,
            path=path,
            query=args,
        )

        response = yield self._send_request(
            request,
            retry_on_dns_fail=retry_on_dns_fail,
            ignore_backoff=ignore_backoff,
        )

        headers = dict(response.headers.getAllRawHeaders())

        try:
            d = _readBodyToFile(response, output_stream, max_size)
            d.addTimeout(self.default_timeout, self.hs.get_reactor())
            length = yield make_deferred_yieldable(d)
        except Exception as e:
            logger.warn(
                "{%s} [%s] Error reading response: %s",
                request.txn_id,
                request.destination,
                e,
            )
            raise
        logger.info(
            "{%s} [%s] Completed: %d %s [%d bytes]",
            request.txn_id,
            request.destination,
            response.code,
            response.phrase.decode('ascii', errors='replace'),
            length,
        )
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
        RequestSendFailed: if the Content-Type header is missing or isn't JSON

    """
    c_type = headers.getRawHeaders(b"Content-Type")
    if c_type is None:
        raise RequestSendFailed(RuntimeError(
            "No Content-Type header"
        ), can_retry=False)

    c_type = c_type[0].decode('ascii')  # only the first header
    val, options = cgi.parse_header(c_type)
    if val != "application/json":
        raise RequestSendFailed(RuntimeError(
            "Content-Type not application/json: was '%s'" % c_type
        ), can_retry=False)


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
