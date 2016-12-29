# -*- coding: utf-8 -*-
# Copyright 2014-2016 OpenMarket Ltd
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


from twisted.internet import defer, reactor, protocol
from twisted.internet.error import DNSLookupError
from twisted.web.client import readBody, HTTPConnectionPool, Agent
from twisted.web.http_headers import Headers
from twisted.web._newclient import ResponseDone

from synapse.http.endpoint import matrix_federation_endpoint
from synapse.util.async import sleep
from synapse.util.logcontext import preserve_context_over_fn
import synapse.metrics

from canonicaljson import encode_canonical_json

from synapse.api.errors import (
    SynapseError, Codes, HttpResponseException,
)

from signedjson.sign import sign_json

import cgi
import simplejson as json
import logging
import random
import sys
import urllib
import urlparse


logger = logging.getLogger(__name__)
outbound_logger = logging.getLogger("synapse.http.outbound")

metrics = synapse.metrics.get_metrics_for(__name__)

outgoing_requests_counter = metrics.register_counter(
    "requests",
    labels=["method"],
)
incoming_responses_counter = metrics.register_counter(
    "responses",
    labels=["method", "code"],
)


MAX_LONG_RETRIES = 10
MAX_SHORT_RETRIES = 3


class MatrixFederationEndpointFactory(object):
    def __init__(self, hs):
        self.tls_server_context_factory = hs.tls_server_context_factory

    def endpointForURI(self, uri):
        destination = uri.netloc

        return matrix_federation_endpoint(
            reactor, destination, timeout=10,
            ssl_context_factory=self.tls_server_context_factory
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
        pool = HTTPConnectionPool(reactor)
        pool.maxPersistentPerHost = 5
        pool.cachedConnectionTimeout = 2 * 60
        self.agent = Agent.usingEndpointFactory(
            reactor, MatrixFederationEndpointFactory(hs), pool=pool
        )
        self.clock = hs.get_clock()
        self.version_string = hs.version_string
        self._next_id = 1

    def _create_url(self, destination, path_bytes, param_bytes, query_bytes):
        return urlparse.urlunparse(
            ("matrix", destination, path_bytes, param_bytes, query_bytes, "")
        )

    @defer.inlineCallbacks
    def _create_request(self, destination, method, path_bytes,
                        body_callback, headers_dict={}, param_bytes=b"",
                        query_bytes=b"", retry_on_dns_fail=True,
                        timeout=None, long_retries=False):
        """ Creates and sends a request to the given url
        """
        headers_dict[b"User-Agent"] = [self.version_string]
        headers_dict[b"Host"] = [destination]

        url_bytes = self._create_url(
            destination, path_bytes, param_bytes, query_bytes
        )

        txn_id = "%s-O-%s" % (method, self._next_id)
        self._next_id = (self._next_id + 1) % (sys.maxint - 1)

        outbound_logger.info(
            "{%s} [%s] Sending request: %s %s",
            txn_id, destination, method, url_bytes
        )

        # XXX: Would be much nicer to retry only at the transaction-layer
        # (once we have reliable transactions in place)
        if long_retries:
            retries_left = MAX_LONG_RETRIES
        else:
            retries_left = MAX_SHORT_RETRIES

        http_url_bytes = urlparse.urlunparse(
            ("", "", path_bytes, param_bytes, query_bytes, "")
        )

        log_result = None
        try:
            while True:
                producer = None
                if body_callback:
                    producer = body_callback(method, http_url_bytes, headers_dict)

                try:
                    def send_request():
                        request_deferred = preserve_context_over_fn(
                            self.agent.request,
                            method,
                            url_bytes,
                            Headers(headers_dict),
                            producer
                        )

                        return self.clock.time_bound_deferred(
                            request_deferred,
                            time_out=timeout / 1000. if timeout else 60,
                        )

                    response = yield preserve_context_over_fn(send_request)

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
                        "{%s} Sending request failed to %s: %s %s: %s - %s",
                        txn_id,
                        destination,
                        method,
                        url_bytes,
                        type(e).__name__,
                        _flatten_response_never_received(e),
                    )

                    log_result = "%s - %s" % (
                        type(e).__name__, _flatten_response_never_received(e),
                    )

                    if retries_left and not timeout:
                        if long_retries:
                            delay = 4 ** (MAX_LONG_RETRIES + 1 - retries_left)
                            delay = min(delay, 60)
                            delay *= random.uniform(0.8, 1.4)
                        else:
                            delay = 0.5 * 2 ** (MAX_SHORT_RETRIES - retries_left)
                            delay = min(delay, 2)
                            delay *= random.uniform(0.8, 1.4)

                        yield sleep(delay)
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
            body = yield preserve_context_over_fn(readBody, response)
            raise HttpResponseException(
                response.code, response.phrase, body
            )

        defer.returnValue(response)

    def sign_request(self, destination, method, url_bytes, headers_dict,
                     content=None):
        request = {
            "method": method,
            "uri": url_bytes,
            "origin": self.server_name,
            "destination": destination,
        }

        if content is not None:
            request["content"] = content

        request = sign_json(request, self.server_name, self.signing_key)

        auth_headers = []

        for key, sig in request["signatures"][self.server_name].items():
            auth_headers.append(bytes(
                "X-Matrix origin=%s,key=\"%s\",sig=\"%s\"" % (
                    self.server_name, key, sig,
                )
            ))

        headers_dict[b"Authorization"] = auth_headers

    @defer.inlineCallbacks
    def put_json(self, destination, path, data={}, json_data_callback=None,
                 long_retries=False, timeout=None):
        """ Sends the specifed json data using PUT

        Args:
            destination (str): The remote server to send the HTTP request
                to.
            path (str): The HTTP path.
            data (dict): A dict containing the data that will be used as
                the request body. This will be encoded as JSON.
            json_data_callback (callable): A callable returning the dict to
                use as the request body.
            long_retries (bool): A boolean that indicates whether we should
                retry for a short or long time.
            timeout(int): How long to try (in ms) the destination for before
                giving up. None indicates no timeout.

        Returns:
            Deferred: Succeeds when we get a 2xx HTTP response. The result
            will be the decoded JSON body. On a 4xx or 5xx error response a
            CodeMessageException is raised.
        """

        if not json_data_callback:
            def json_data_callback():
                return data

        def body_callback(method, url_bytes, headers_dict):
            json_data = json_data_callback()
            self.sign_request(
                destination, method, url_bytes, headers_dict, json_data
            )
            producer = _JsonProducer(json_data)
            return producer

        response = yield self._create_request(
            destination.encode("ascii"),
            "PUT",
            path.encode("ascii"),
            body_callback=body_callback,
            headers_dict={"Content-Type": ["application/json"]},
            long_retries=long_retries,
            timeout=timeout,
        )

        if 200 <= response.code < 300:
            # We need to update the transactions table to say it was sent?
            check_content_type_is_json(response.headers)

        body = yield preserve_context_over_fn(readBody, response)
        defer.returnValue(json.loads(body))

    @defer.inlineCallbacks
    def post_json(self, destination, path, data={}, long_retries=False,
                  timeout=None):
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

        Returns:
            Deferred: Succeeds when we get a 2xx HTTP response. The result
            will be the decoded JSON body. On a 4xx or 5xx error response a
            CodeMessageException is raised.
        """

        def body_callback(method, url_bytes, headers_dict):
            self.sign_request(
                destination, method, url_bytes, headers_dict, data
            )
            return _JsonProducer(data)

        response = yield self._create_request(
            destination.encode("ascii"),
            "POST",
            path.encode("ascii"),
            body_callback=body_callback,
            headers_dict={"Content-Type": ["application/json"]},
            long_retries=long_retries,
            timeout=timeout,
        )

        if 200 <= response.code < 300:
            # We need to update the transactions table to say it was sent?
            check_content_type_is_json(response.headers)

        body = yield preserve_context_over_fn(readBody, response)

        defer.returnValue(json.loads(body))

    @defer.inlineCallbacks
    def get_json(self, destination, path, args={}, retry_on_dns_fail=True,
                 timeout=None):
        """ GETs some json from the given host homeserver and path

        Args:
            destination (str): The remote server to send the HTTP request
                to.
            path (str): The HTTP path.
            args (dict): A dictionary used to create query strings, defaults to
                None.
            timeout (int): How long to try (in ms) the destination for before
                giving up. None indicates no timeout and that the request will
                be retried.
        Returns:
            Deferred: Succeeds when we get *any* HTTP response.

            The result of the deferred is a tuple of `(code, response)`,
            where `response` is a dict representing the decoded JSON body.
        """
        logger.debug("get_json args: %s", args)

        encoded_args = {}
        for k, vs in args.items():
            if isinstance(vs, basestring):
                vs = [vs]
            encoded_args[k] = [v.encode("UTF-8") for v in vs]

        query_bytes = urllib.urlencode(encoded_args, True)
        logger.debug("Query bytes: %s Retry DNS: %s", args, retry_on_dns_fail)

        def body_callback(method, url_bytes, headers_dict):
            self.sign_request(destination, method, url_bytes, headers_dict)
            return None

        response = yield self._create_request(
            destination.encode("ascii"),
            "GET",
            path.encode("ascii"),
            query_bytes=query_bytes,
            body_callback=body_callback,
            retry_on_dns_fail=retry_on_dns_fail,
            timeout=timeout,
        )

        if 200 <= response.code < 300:
            # We need to update the transactions table to say it was sent?
            check_content_type_is_json(response.headers)

        body = yield preserve_context_over_fn(readBody, response)

        defer.returnValue(json.loads(body))

    @defer.inlineCallbacks
    def get_file(self, destination, path, output_stream, args={},
                 retry_on_dns_fail=True, max_size=None):
        """GETs a file from a given homeserver
        Args:
            destination (str): The remote server to send the HTTP request to.
            path (str): The HTTP path to GET.
            output_stream (file): File to write the response body to.
            args (dict): Optional dictionary used to create the query string.
        Returns:
            A (int,dict) tuple of the file length and a dict of the response
            headers.
        """

        encoded_args = {}
        for k, vs in args.items():
            if isinstance(vs, basestring):
                vs = [vs]
            encoded_args[k] = [v.encode("UTF-8") for v in vs]

        query_bytes = urllib.urlencode(encoded_args, True)
        logger.debug("Query bytes: %s Retry DNS: %s", args, retry_on_dns_fail)

        def body_callback(method, url_bytes, headers_dict):
            self.sign_request(destination, method, url_bytes, headers_dict)
            return None

        response = yield self._create_request(
            destination.encode("ascii"),
            "GET",
            path.encode("ascii"),
            query_bytes=query_bytes,
            body_callback=body_callback,
            retry_on_dns_fail=retry_on_dns_fail
        )

        headers = dict(response.headers.getAllRawHeaders())

        try:
            length = yield preserve_context_over_fn(
                _readBodyToFile,
                response, output_stream, max_size
            )
        except:
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


class _JsonProducer(object):
    """ Used by the twisted http client to create the HTTP body from json
    """
    def __init__(self, jsn):
        self.reset(jsn)

    def reset(self, jsn):
        self.body = encode_canonical_json(jsn)
        self.length = len(self.body)

    def startProducing(self, consumer):
        consumer.write(self.body)
        return defer.succeed(None)

    def pauseProducing(self):
        pass

    def stopProducing(self):
        pass

    def resumeProducing(self):
        pass


def _flatten_response_never_received(e):
    if hasattr(e, "reasons"):
        return ", ".join(
            _flatten_response_never_received(f.value)
            for f in e.reasons
        )
    else:
        return "%s: %s" % (type(e).__name__, e.message,)


def check_content_type_is_json(headers):
    """
    Check that a set of HTTP headers have a Content-Type header, and that it
    is application/json.

    Args:
        headers (twisted.web.http_headers.Headers): headers to check

    Raises:
        RuntimeError if the

    """
    c_type = headers.getRawHeaders("Content-Type")
    if c_type is None:
        raise RuntimeError(
            "No Content-Type header"
        )

    c_type = c_type[0]  # only the first header
    val, options = cgi.parse_header(c_type)
    if val != "application/json":
        raise RuntimeError(
            "Content-Type not application/json: was '%s'" % c_type
        )
