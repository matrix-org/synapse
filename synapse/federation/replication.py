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

"""This layer is responsible for replicating with remote home servers using
a given transport.
"""

from .federation_client import FederationClient
from .federation_server import FederationServer

from .persistence import TransactionActions

import logging


logger = logging.getLogger(__name__)


class ReplicationLayer(FederationClient, FederationServer):
    """This layer is responsible for replicating with remote home servers over
    the given transport. I.e., does the sending and receiving of PDUs to
    remote home servers.

    The layer communicates with the rest of the server via a registered
    ReplicationHandler.

    In more detail, the layer:
        * Receives incoming data and processes it into transactions and pdus.
        * Fetches any PDUs it thinks it might have missed.
        * Keeps the current state for contexts up to date by applying the
          suitable conflict resolution.
        * Sends outgoing pdus wrapped in transactions.
        * Fills out the references to previous pdus/transactions appropriately
          for outgoing data.
    """

    def __init__(self, hs, transport_layer):
        self.server_name = hs.hostname

        self.keyring = hs.get_keyring()

        self.transport_layer = transport_layer

        self.federation_client = self

        self.store = hs.get_datastore()

        self.handler = None
        self.edu_handlers = {}
        self.query_handlers = {}

        self._clock = hs.get_clock()

        self.transaction_actions = TransactionActions(self.store)

        self.hs = hs

        super(ReplicationLayer, self).__init__(hs)

    def __str__(self):
        return "<ReplicationLayer(%s)>" % self.server_name
