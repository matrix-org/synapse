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


from twisted.web.http import HTTPClient
from twisted.internet.protocol import Factory
from twisted.internet import defer, reactor
from synapse.http.endpoint import matrix_federation_endpoint
from synapse.util.logcontext import (
    preserve_context_over_fn, preserve_context_over_deferred
)
import simplejson as json
import logging


logger = logging.getLogger(__name__)

KEY_API_V1 = b"/_matrix/key/v1/"


@defer.inlineCallbacks
def fetch_server_key(server_name, ssl_context_factory, path=KEY_API_V1):
    """Fetch the keys for a remote server."""

    factory = SynapseKeyClientFactory()
    factory.path = path
    factory.host = server_name
    endpoint = matrix_federation_endpoint(
        reactor, server_name, ssl_context_factory, timeout=30
    )

    for i in range(5):
        try:
            protocol = yield preserve_context_over_fn(
                endpoint.connect, factory
            )
            server_response, server_certificate = yield preserve_context_over_deferred(
                protocol.remote_key
            )
            defer.returnValue((server_response, server_certificate))
            return
        except SynapseKeyClientError as e:
            logger.exception("Error getting key for %r" % (server_name,))
            if e.status.startswith("4"):
                # Don't retry for 4xx responses.
                raise IOError("Cannot get key for %r" % server_name)
        except Exception as e:
            logger.exception(e)
    raise IOError("Cannot get key for %r" % server_name)


class SynapseKeyClientError(Exception):
    """The key wasn't retrieved from the remote server."""
    status = None
    pass


class SynapseKeyClientProtocol(HTTPClient):
    """Low level HTTPS client which retrieves an application/json response from
    the server and extracts the X.509 certificate for the remote peer from the
    SSL connection."""

    timeout = 30

    def __init__(self):
        self.remote_key = defer.Deferred()
        self.host = None
        self._peer = None

    def connectionMade(self):
        self._peer = self.transport.getPeer()
        logger.debug("Connected to %s", self._peer)

        self.sendCommand(b"GET", self.path)
        if self.host:
            self.sendHeader(b"Host", self.host)
        self.endHeaders()
        self.timer = reactor.callLater(
            self.timeout,
            self.on_timeout
        )

    def errback(self, error):
        if not self.remote_key.called:
            self.remote_key.errback(error)

    def callback(self, result):
        if not self.remote_key.called:
            self.remote_key.callback(result)

    def handleStatus(self, version, status, message):
        if status != b"200":
            # logger.info("Non-200 response from %s: %s %s",
            #            self.transport.getHost(), status, message)
            error = SynapseKeyClientError(
                "Non-200 response %r from %r" % (status, self.host)
            )
            error.status = status
            self.errback(error)
            self.transport.abortConnection()

    def handleResponse(self, response_body_bytes):
        try:
            json_response = json.loads(response_body_bytes)
        except ValueError:
            # logger.info("Invalid JSON response from %s",
            #            self.transport.getHost())
            self.transport.abortConnection()
            return

        certificate = self.transport.getPeerCertificate()
        self.callback((json_response, certificate))
        self.transport.abortConnection()
        self.timer.cancel()

    def on_timeout(self):
        logger.debug(
            "Timeout waiting for response from %s: %s",
            self.host, self._peer,
        )
        self.errback(IOError("Timeout waiting for response"))
        self.transport.abortConnection()


class SynapseKeyClientFactory(Factory):
    def protocol(self):
        protocol = SynapseKeyClientProtocol()
        protocol.path = self.path
        protocol.host = self.host
        return protocol
