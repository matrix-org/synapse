# -*- coding: utf-8 -*-
# Copyright 2019 New Vector Ltd
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

from twisted.internet import defer

from synapse.api.errors import HttpResponseException
from synapse.federation.persistence import TransactionActions
from synapse.federation.units import Transaction
from synapse.util.metrics import measure_func

logger = logging.getLogger(__name__)


class TransactionManager(object):
    """Helper class which handles building and sending transactions

    shared between PerDestinationQueue objects
    """
    def __init__(self, hs):
        self._server_name = hs.hostname
        self.clock = hs.get_clock()   # nb must be called this for @measure_func
        self._store = hs.get_datastore()
        self._transaction_actions = TransactionActions(self._store)
        self._transport_layer = hs.get_federation_transport_client()

        # HACK to get unique tx id
        self._next_txn_id = int(self.clock.time_msec())

    @measure_func("_send_new_transaction")
    @defer.inlineCallbacks
    def send_new_transaction(self, destination, pending_pdus, pending_edus):

        # Sort based on the order field
        pending_pdus.sort(key=lambda t: t[1])
        pdus = [x[0] for x in pending_pdus]
        edus = pending_edus

        success = True

        logger.debug("TX [%s] _attempt_new_transaction", destination)

        txn_id = str(self._next_txn_id)

        logger.debug(
            "TX [%s] {%s} Attempting new transaction"
            " (pdus: %d, edus: %d)",
            destination, txn_id,
            len(pdus),
            len(edus),
        )

        logger.debug("TX [%s] Persisting transaction...", destination)

        transaction = Transaction.create_new(
            origin_server_ts=int(self.clock.time_msec()),
            transaction_id=txn_id,
            origin=self._server_name,
            destination=destination,
            pdus=pdus,
            edus=edus,
        )

        self._next_txn_id += 1

        yield self._transaction_actions.prepare_to_send(transaction)

        logger.debug("TX [%s] Persisted transaction", destination)
        logger.info(
            "TX [%s] {%s} Sending transaction [%s],"
            " (PDUs: %d, EDUs: %d)",
            destination, txn_id,
            transaction.transaction_id,
            len(pdus),
            len(edus),
        )

        # Actually send the transaction

        # FIXME (erikj): This is a bit of a hack to make the Pdu age
        # keys work
        def json_data_cb():
            data = transaction.get_dict()
            now = int(self.clock.time_msec())
            if "pdus" in data:
                for p in data["pdus"]:
                    if "age_ts" in p:
                        unsigned = p.setdefault("unsigned", {})
                        unsigned["age"] = now - int(p["age_ts"])
                        del p["age_ts"]
            return data

        try:
            response = yield self._transport_layer.send_transaction(
                transaction, json_data_cb
            )
            code = 200
        except HttpResponseException as e:
            code = e.code
            response = e.response

            if e.code in (401, 404, 429) or 500 <= e.code:
                logger.info(
                    "TX [%s] {%s} got %d response",
                    destination, txn_id, code
                )
                raise e

        logger.info(
            "TX [%s] {%s} got %d response",
            destination, txn_id, code
        )

        yield self._transaction_actions.delivered(
            transaction, code, response
        )

        logger.debug("TX [%s] {%s} Marked as delivered", destination, txn_id)

        if code == 200:
            for e_id, r in response.get("pdus", {}).items():
                if "error" in r:
                    logger.warn(
                        "TX [%s] {%s} Remote returned error for %s: %s",
                        destination, txn_id, e_id, r,
                    )
        else:
            for p in pdus:
                logger.warn(
                    "TX [%s] {%s} Failed to send event %s",
                    destination, txn_id, p.event_id,
                )
            success = False

        defer.returnValue(success)
