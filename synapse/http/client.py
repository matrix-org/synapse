# -*- coding: utf-8 -*-
# Copyright 2014 OpenMarket Ltd
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


from twisted.internet import defer, reactor
from twisted.internet.error import DNSLookupError
from twisted.web.client import _AgentBase, _URI, readBody, FileBodyProducer, PartialDownloadError
from twisted.web.http_headers import Headers

from synapse.http.endpoint import matrix_endpoint
from synapse.util.async import sleep

from syutil.jsonutil import encode_canonical_json

from synapse.api.errors import CodeMessageException, SynapseError

from StringIO import StringIO

import json
import logging
import urllib


logger = logging.getLogger(__name__)


class MatrixHttpAgent(_AgentBase):

    def __init__(self, reactor, pool=None):
        _AgentBase.__init__(self, reactor, pool)

    def request(self, destination, endpoint, method, path, params, query,
                headers, body_producer):

        host = b""
        port = 0
        fragment = b""

        parsed_URI = _URI(b"http", destination, host, port, path, params,
                          query, fragment)

        # Set the connection pool key to be the destination.
        key = destination

        return self._requestWithEndpoint(key, endpoint, method, parsed_URI,
                                         headers, body_producer,
                                         parsed_URI.originForm)


class BaseHttpClient(object):
    """Base class for HTTP clients using twisted.
    """

    def __init__(self, hs):
        self.agent = MatrixHttpAgent(reactor)
        self.hs = hs

    @defer.inlineCallbacks
    def _create_request(self, destination, method, path_bytes, param_bytes=b"",
                        query_bytes=b"", producer=None, headers_dict={},
                        retry_on_dns_fail=True, on_send_callback=None):
        """ Creates and sends a request to the given url
        """
        headers_dict[b"User-Agent"] = [b"Synapse"]
        headers_dict[b"Host"] = [destination]

        logger.debug("Sending request to %s: %s %s;%s?%s",
                     destination, method, path_bytes, param_bytes, query_bytes)

        logger.debug(
            "Types: %s",
            [
                type(destination), type(method), type(path_bytes),
                type(param_bytes),
                type(query_bytes)
            ]
        )

        retries_left = 5

        endpoint = self._getEndpoint(reactor, destination);

        while True:
            if on_send_callback:
                on_send_callback(destination, method, path_bytes, producer)

            try:
                response = yield self.agent.request(
                    destination,
                    endpoint,
                    method,
                    path_bytes,
                    param_bytes,
                    query_bytes,
                    Headers(headers_dict),
                    producer
                )

                logger.debug("Got response to %s", method)
                break
            except Exception as e:
                if not retry_on_dns_fail and isinstance(e, DNSLookupError):
                    logger.warn("DNS Lookup failed to %s with %s", destination,
                                e)
                    raise SynapseError(400, "Domain specified not found.")

                logger.exception("Got error in _create_request")
                _print_ex(e)

                if retries_left:
                    yield sleep(2 ** (5 - retries_left))
                    retries_left -= 1
                else:
                    raise

        if 200 <= response.code < 300:
            # We need to update the transactions table to say it was sent?
            pass
        else:
            # :'(
            # Update transactions table?
            logger.error(
                "Got response %d %s", response.code, response.phrase
            )
            raise CodeMessageException(
                response.code, response.phrase
            )

        defer.returnValue(response)


class MatrixHttpClient(BaseHttpClient):
    """ Wrapper around the twisted HTTP client api. Implements 

    Attributes:
        agent (twisted.web.client.Agent): The twisted Agent used to send the
            requests.
    """

    RETRY_DNS_LOOKUP_FAILURES = "__retry_dns"

    @defer.inlineCallbacks
    def put_json(self, destination, path, data, on_send_callback=None):
        """ Sends the specifed json data using PUT

        Args:
            destination (str): The remote server to send the HTTP request
                to.
            path (str): The HTTP path.
            data (dict): A dict containing the data that will be used as
                the request body. This will be encoded as JSON.

        Returns:
            Deferred: Succeeds when we get a 2xx HTTP response. The result
            will be the decoded JSON body. On a 4xx or 5xx error response a
            CodeMessageException is raised.
        """
        response = yield self._create_request(
            destination.encode("ascii"),
            "PUT",
            path.encode("ascii"),
            producer=_JsonProducer(data),
            headers_dict={"Content-Type": ["application/json"]},
            on_send_callback=on_send_callback,
        )

        logger.debug("Getting resp body")
        body = yield readBody(response)
        logger.debug("Got resp body")

        defer.returnValue((response.code, body))

    @defer.inlineCallbacks
    def get_json(self, destination, path, args={}):
        """ Get's some json from the given host homeserver and path

        Args:
            destination (str): The remote server to send the HTTP request
                to.
            path (str): The HTTP path.
            args (dict): A dictionary used to create query strings, defaults to
                None.
                **Note**: The value of each key is assumed to be an iterable
                and *not* a string.

        Returns:
            Deferred: Succeeds when we get *any* HTTP response.

            The result of the deferred is a tuple of `(code, response)`,
            where `response` is a dict representing the decoded JSON body.
        """
        logger.debug("get_json args: %s", args)

        retry_on_dns_fail = True
        if HttpClient.RETRY_DNS_LOOKUP_FAILURES in args:
            # FIXME: This isn't ideal, but the interface exposed in get_json
            # isn't comprehensive enough to give caller's any control over
            # their connection mechanics.
            retry_on_dns_fail = args.pop(HttpClient.RETRY_DNS_LOOKUP_FAILURES)

        query_bytes = urllib.urlencode(args, True)
        logger.debug("Query bytes: %s Retry DNS: %s", args, retry_on_dns_fail)

        response = yield self._create_request(
            destination.encode("ascii"),
            "GET",
            path.encode("ascii"),
            query_bytes=query_bytes,
            retry_on_dns_fail=retry_on_dns_fail
        )

        body = yield readBody(response)

        defer.returnValue(json.loads(body))


    def _getEndpoint(self, reactor, destination):
        return matrix_endpoint(
            reactor, destination, timeout=10,
            ssl_context_factory=self.hs.tls_context_factory
        )


class IdentityServerHttpClient(BaseHttpClient):
    """Separate HTTP client for talking to the Identity servers since they
    don't use SRV records and talk x-www-form-urlencoded rather than JSON.
    """
    def _getEndpoint(self, reactor, destination):
        #TODO: This should be talking TLS
        return matrix_endpoint(reactor, destination, timeout=10)

    @defer.inlineCallbacks
    def post_urlencoded_get_json(self, destination, path, args={}):
        if destination in _destination_mappings:
            destination = _destination_mappings[destination]

        logger.debug("post_urlencoded_get_json args: %s", args)
        query_bytes = urllib.urlencode(args, True)

        response = yield self._create_request(
            destination.encode("ascii"),
            "POST",
            path.encode("ascii"),
            producer=FileBodyProducer(StringIO(urllib.urlencode(args))),
            headers_dict={
                "Content-Type": ["application/x-www-form-urlencoded"]
            }
        )

        body = yield readBody(response)

        defer.returnValue(json.loads(body))


class CaptchaServerHttpClient(MatrixHttpClient):
    """Separate HTTP client for talking to google's captcha servers"""

    def _getEndpoint(self, reactor, destination):
        return matrix_endpoint(reactor, destination, timeout=10)

    @defer.inlineCallbacks
    def post_urlencoded_get_raw(self, destination, path, accept_partial=False,
                                args={}):
        if destination in _destination_mappings:
            destination = _destination_mappings[destination]

        query_bytes = urllib.urlencode(args, True)

        response = yield self._create_request(
            destination.encode("ascii"),
            "POST",
            path.encode("ascii"),
            producer=FileBodyProducer(StringIO(urllib.urlencode(args))),
            headers_dict={
                "Content-Type": ["application/x-www-form-urlencoded"]
            }
        )

        try:
            body = yield readBody(response)
            defer.returnValue(body)
        except PartialDownloadError as e:
            if accept_partial:
                defer.returnValue(e.response)
            else:
                raise e

def _print_ex(e):
    if hasattr(e, "reasons") and e.reasons:
        for ex in e.reasons:
            _print_ex(ex)
    else:
        logger.exception(e)


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
