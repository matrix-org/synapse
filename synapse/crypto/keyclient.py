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

from twisted.web.http import HTTPClient
from twisted.internet import defer, reactor
from twisted.internet.protocol import ClientFactory
from twisted.names.srvconnect import SRVConnector
import json
import logging


logger = logging.getLogger(__name__)


@defer.inlineCallbacks
def fetch_server_key(server_name, ssl_context_factory):
    """Fetch the keys for a remote server."""

    factory = SynapseKeyClientFactory()

    SRVConnector(
        reactor, "matrix", server_name, factory,
        protocol="tcp", connectFuncName="connectSSL", defaultPort=443,
        connectFuncKwArgs=dict(contextFactory=ssl_context_factory)).connect()

    server_key, server_certificate = yield factory.remote_key

    defer.returnValue((server_key, server_certificate))


class SynapseKeyClientError(Exception):
    """The key wasn't retireved from the remote server."""
    pass


class SynapseKeyClientProtocol(HTTPClient):
    """Low level HTTPS client which retrieves an application/json response from
    the server and extracts the X.509 certificate for the remote peer from the
    SSL connection."""

    def connectionMade(self):
        logger.debug("Connected to %s", self.transport.getHost())
        self.sendCommand(b"GET", b"/key")
        self.endHeaders()
        self.timer = reactor.callLater(
            self.factory.timeout_seconds,
            self.on_timeout
        )

    def handleStatus(self, version, status, message):
        if status != b"200":
            logger.info("Non-200 response from %s: %s %s",
                        self.transport.getHost(), status, message)
            self.transport.abortConnection()

    def handleResponse(self, response_body_bytes):
        try:
            json_response = json.loads(response_body_bytes)
        except ValueError:
            logger.info("Invalid JSON response from %s",
                        self.transport.getHost())
            self.transport.abortConnection()
            return

        certificate = self.transport.getPeerCertificate()
        self.factory.on_remote_key((json_response, certificate))
        self.transport.abortConnection()
        self.timer.cancel()

    def on_timeout(self):
        logger.debug("Timeout waiting for response from %s",
                     self.transport.getHost())
        self.transport.abortConnection()


class SynapseKeyClientFactory(ClientFactory):
    protocol = SynapseKeyClientProtocol
    max_retries = 5
    timeout_seconds = 30

    def __init__(self):
        self.succeeded = False
        self.retries = 0
        self.remote_key = defer.Deferred()

    def on_remote_key(self, key):
        self.succeeded = True
        self.remote_key.callback(key)

    def retry_connection(self, connector):
        self.retries += 1
        if self.retries < self.max_retries:
            connector.connector = None
            connector.connect()
        else:
            self.remote_key.errback(
                SynapseKeyClientError("Max retries exceeded"))

    def clientConnectionFailed(self, connector, reason):
        logger.info("Connection failed %s", reason)
        self.retry_connection(connector)

    def clientConnectionLost(self, connector, reason):
        logger.info("Connection lost %s", reason)
        if not self.succeeded:
            self.retry_connection(connector)
