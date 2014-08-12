# -*- coding: utf-8 -*-
# Copyright 2014 matrix.org
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
from twisted.web.client import _AgentBase, _URI, readBody
from twisted.web.http_headers import Headers

from synapse.http.endpoint import matrix_endpoint
from synapse.util.async import sleep

from syutil.jsonutil import encode_canonical_json

from synapse.api.errors import CodeMessageException

import json
import logging
import urllib


logger = logging.getLogger(__name__)


_destination_mappings = {
    "red": "localhost:8080",
    "blue": "localhost:8081",
    "green": "localhost:8082",
}


class HttpClient(object):
    """ Interface for talking json over http
    """

    def put_json(self, destination, path, data):
        """ Sends the specifed json data using PUT

        Args:
            destination (str): The remote server to send the HTTP request
                to.
            path (str): The HTTP path.
            data (dict): A dict containing the data that will be used as
                the request body. This will be encoded as JSON.

        Returns:
            Deferred: Succeeds when we get *any* HTTP response.

            The result of the deferred is a tuple of `(code, response)`,
            where `response` is a dict representing the decoded JSON body.
        """
        pass

    def get_json(self, destination, path, args=None):
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
        pass


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


class TwistedHttpClient(HttpClient):
    """ Wrapper around the twisted HTTP client api.

    Attributes:
        agent (twisted.web.client.Agent): The twisted Agent used to send the
            requests.
    """

    def __init__(self):
        self.agent = MatrixHttpAgent(reactor)

    @defer.inlineCallbacks
    def put_json(self, destination, path, data):
        if destination in _destination_mappings:
            destination = _destination_mappings[destination]

        response = yield self._create_request(
            destination.encode("ascii"),
            "PUT",
            path.encode("ascii"),
            producer=_JsonProducer(data),
            headers_dict={"Content-Type": ["application/json"]}
        )

        logger.debug("Getting resp body")
        body = yield readBody(response)
        logger.debug("Got resp body")

        defer.returnValue((response.code, body))

    @defer.inlineCallbacks
    def get_json(self, destination, path, args={}):
        if destination in _destination_mappings:
            destination = _destination_mappings[destination]

        logger.debug("get_json args: %s", args)
        query_bytes = urllib.urlencode(args, True)

        response = yield self._create_request(
            destination.encode("ascii"),
            "GET",
            path.encode("ascii"),
            query_bytes
        )

        body = yield readBody(response)

        defer.returnValue(json.loads(body))

    @defer.inlineCallbacks
    def _create_request(self, destination, method, path_bytes, param_bytes=b"",
                        query_bytes=b"", producer=None, headers_dict={}):
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

        # TODO: setup and pass in an ssl_context to enable TLS
        endpoint = matrix_endpoint(reactor, destination, timeout=10)

        while True:
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
        self.body = encode_canonical_json(jsn)
        self.length = len(self.body)

    def startProducing(self, consumer):
        consumer.write(self.body)
        return defer.succeed(None)

    def pauseProducing(self):
        pass

    def stopProducing(self):
        pass
