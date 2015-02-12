# -*- coding: utf-8 -*-
# Copyright 2014, 2015 OpenMarket Ltd
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

"""The transport layer is responsible for both sending transactions to remote
home servers and receiving a variety of requests from other home servers.

By default this is done over HTTPS (and all home servers are required to
support HTTPS), however individual pairings of servers may decide to
communicate over a different (albeit still reliable) protocol.
"""

from .server import TransportLayerServer
from .client import TransportLayerClient


class TransportLayer(TransportLayerServer, TransportLayerClient):
    """This is a basic implementation of the transport layer that translates
    transactions and other requests to/from HTTP.

    Attributes:
        server_name (str): Local home server host

        server (synapse.http.server.HttpServer): the http server to
                register listeners on

        client (synapse.http.client.HttpClient): the http client used to
                send requests

        request_handler (TransportRequestHandler): The handler to fire when we
            receive requests for data.

        received_handler (TransportReceivedHandler): The handler to fire when
            we receive data.
    """

    def __init__(self, homeserver, server_name, server, client):
        """
        Args:
            server_name (str): Local home server host
            server (synapse.protocol.http.HttpServer): the http server to
                register listeners on
            client (synapse.protocol.http.HttpClient): the http client used to
                send requests
        """
        self.keyring = homeserver.get_keyring()
        self.server_name = server_name
        self.server = server
        self.client = client
        self.request_handler = None
        self.received_handler = None
