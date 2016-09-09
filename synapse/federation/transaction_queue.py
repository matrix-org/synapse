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


from twisted.internet import defer

from .persistence import TransactionActions
from .units import Transaction, Edu

from synapse.api.errors import HttpResponseException
from synapse.util.async import run_on_reactor
from synapse.util.logcontext import preserve_context_over_fn
from synapse.util.retryutils import (
    get_retry_limiter, NotRetryingDestination,
)
from synapse.util.metrics import measure_func
import synapse.metrics

import logging


logger = logging.getLogger(__name__)

metrics = synapse.metrics.get_metrics_for(__name__)


class TransactionQueue(object):
    """This class makes sure we only have one transaction in flight at
    a time for a given destination.

    It batches pending PDUs into single transactions.
    """

    def __init__(self, hs, transport_layer):
        self.server_name = hs.hostname

        self.store = hs.get_datastore()
        self.transaction_actions = TransactionActions(self.store)

        self.transport_layer = transport_layer

        self.clock = hs.get_clock()

        # Is a mapping from destinations -> deferreds. Used to keep track
        # of which destinations have transactions in flight and when they are
        # done
        self.pending_transactions = {}

        metrics.register_callback(
            "pending_destinations",
            lambda: len(self.pending_transactions),
        )

        # Is a mapping from destination -> list of
        # tuple(pending pdus, deferred, order)
        self.pending_pdus_by_dest = pdus = {}
        # destination -> list of tuple(edu, deferred)
        self.pending_edus_by_dest = edus = {}

        metrics.register_callback(
            "pending_pdus",
            lambda: sum(map(len, pdus.values())),
        )
        metrics.register_callback(
            "pending_edus",
            lambda: sum(map(len, edus.values())),
        )

        # destination -> list of tuple(failure, deferred)
        self.pending_failures_by_dest = {}

        self.last_device_stream_id_by_dest = {}

        # HACK to get unique tx id
        self._next_txn_id = int(self.clock.time_msec())

    def can_send_to(self, destination):
        """Can we send messages to the given server?

        We can't send messages to ourselves. If we are running on localhost
        then we can only federation with other servers running on localhost.
        Otherwise we only federate with servers on a public domain.

        Args:
            destination(str): The server we are possibly trying to send to.
        Returns:
            bool: True if we can send to the server.
        """

        if destination == self.server_name:
            return False
        if self.server_name.startswith("localhost"):
            return destination.startswith("localhost")
        else:
            return not destination.startswith("localhost")

    def enqueue_pdu(self, pdu, destinations, order):
        # We loop through all destinations to see whether we already have
        # a transaction in progress. If we do, stick it in the pending_pdus
        # table and we'll get back to it later.

        destinations = set(destinations)
        destinations = set(
            dest for dest in destinations if self.can_send_to(dest)
        )

        logger.debug("Sending to: %s", str(destinations))

        if not destinations:
            return

        for destination in destinations:
            self.pending_pdus_by_dest.setdefault(destination, []).append(
                (pdu, order)
            )

            preserve_context_over_fn(
                self._attempt_new_transaction, destination
            )

    def enqueue_edu(self, edu):
        destination = edu.destination

        if not self.can_send_to(destination):
            return

        self.pending_edus_by_dest.setdefault(destination, []).append(edu)

        preserve_context_over_fn(
            self._attempt_new_transaction, destination
        )

    def enqueue_failure(self, failure, destination):
        if destination == self.server_name or destination == "localhost":
            return

        if not self.can_send_to(destination):
            return

        self.pending_failures_by_dest.setdefault(
            destination, []
        ).append(failure)

        preserve_context_over_fn(
            self._attempt_new_transaction, destination
        )

    def enqueue_device_messages(self, destination):
        if destination == self.server_name or destination == "localhost":
            return

        if not self.can_send_to(destination):
            return

        preserve_context_over_fn(
            self._attempt_new_transaction, destination
        )

    @defer.inlineCallbacks
    def _attempt_new_transaction(self, destination):
        # list of (pending_pdu, deferred, order)
        if destination in self.pending_transactions:
            # XXX: pending_transactions can get stuck on by a never-ending
            # request at which point pending_pdus_by_dest just keeps growing.
            # we need application-layer timeouts of some flavour of these
            # requests
            logger.debug(
                "TX [%s] Transaction already in progress",
                destination
            )
            return

        try:
            self.pending_transactions[destination] = 1

            yield run_on_reactor()

            while True:
                    pending_pdus = self.pending_pdus_by_dest.pop(destination, [])
                    pending_edus = self.pending_edus_by_dest.pop(destination, [])
                    pending_failures = self.pending_failures_by_dest.pop(destination, [])

                    limiter = yield get_retry_limiter(
                        destination,
                        self.clock,
                        self.store,
                    )

                    device_message_edus, device_stream_id = (
                        yield self._get_new_device_messages(destination)
                    )

                    pending_edus.extend(device_message_edus)

                    if pending_pdus:
                        logger.debug("TX [%s] len(pending_pdus_by_dest[dest]) = %d",
                                     destination, len(pending_pdus))

                    if not pending_pdus and not pending_edus and not pending_failures:
                        logger.debug("TX [%s] Nothing to send", destination)
                        self.last_device_stream_id_by_dest[destination] = (
                            device_stream_id
                        )
                        return

                    success = yield self._send_new_transaction(
                        destination, pending_pdus, pending_edus, pending_failures,
                        device_stream_id,
                        should_delete_from_device_stream=bool(device_message_edus),
                        limiter=limiter,
                    )
                    if not success:
                        break
        except NotRetryingDestination:
            logger.info(
                "TX [%s] not ready for retry yet - "
                "dropping transaction for now",
                destination,
            )
        finally:
            # We want to be *very* sure we delete this after we stop processing
            self.pending_transactions.pop(destination, None)

    @defer.inlineCallbacks
    def _get_new_device_messages(self, destination):
        last_device_stream_id = self.last_device_stream_id_by_dest.get(destination, 0)
        to_device_stream_id = self.store.get_to_device_stream_token()
        contents, stream_id = yield self.store.get_new_device_msgs_for_remote(
            destination, last_device_stream_id, to_device_stream_id
        )
        edus = [
            Edu(
                origin=self.server_name,
                destination=destination,
                edu_type="m.direct_to_device",
                content=content,
            )
            for content in contents
        ]
        defer.returnValue((edus, stream_id))

    @measure_func("_send_new_transaction")
    @defer.inlineCallbacks
    def _send_new_transaction(self, destination, pending_pdus, pending_edus,
                              pending_failures, device_stream_id,
                              should_delete_from_device_stream, limiter):

        # Sort based on the order field
        pending_pdus.sort(key=lambda t: t[1])
        pdus = [x[0] for x in pending_pdus]
        edus = pending_edus
        failures = [x.get_dict() for x in pending_failures]

        success = True

        try:
            logger.debug("TX [%s] _attempt_new_transaction", destination)

            txn_id = str(self._next_txn_id)

            logger.debug(
                "TX [%s] {%s} Attempting new transaction"
                " (pdus: %d, edus: %d, failures: %d)",
                destination, txn_id,
                len(pdus),
                len(edus),
                len(failures)
            )

            logger.debug("TX [%s] Persisting transaction...", destination)

            transaction = Transaction.create_new(
                origin_server_ts=int(self.clock.time_msec()),
                transaction_id=txn_id,
                origin=self.server_name,
                destination=destination,
                pdus=pdus,
                edus=edus,
                pdu_failures=failures,
            )

            self._next_txn_id += 1

            yield self.transaction_actions.prepare_to_send(transaction)

            logger.debug("TX [%s] Persisted transaction", destination)
            logger.info(
                "TX [%s] {%s} Sending transaction [%s],"
                " (PDUs: %d, EDUs: %d, failures: %d)",
                destination, txn_id,
                transaction.transaction_id,
                len(pdus),
                len(edus),
                len(failures),
            )

            with limiter:
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
                    response = yield self.transport_layer.send_transaction(
                        transaction, json_data_cb
                    )
                    code = 200

                    if response:
                        for e_id, r in response.get("pdus", {}).items():
                            if "error" in r:
                                logger.warn(
                                    "Transaction returned error for %s: %s",
                                    e_id, r,
                                )
                except HttpResponseException as e:
                    code = e.code
                    response = e.response

                logger.info(
                    "TX [%s] {%s} got %d response",
                    destination, txn_id, code
                )

                logger.debug("TX [%s] Sent transaction", destination)
                logger.debug("TX [%s] Marking as delivered...", destination)

            yield self.transaction_actions.delivered(
                transaction, code, response
            )

            logger.debug("TX [%s] Marked as delivered", destination)

            if code != 200:
                for p in pdus:
                    logger.info(
                        "Failed to send event %s to %s", p.event_id, destination
                    )
                success = False
            else:
                # Remove the acknowledged device messages from the database
                if should_delete_from_device_stream:
                    yield self.store.delete_device_msgs_for_remote(
                        destination, device_stream_id
                    )
                self.last_device_stream_id_by_dest[destination] = device_stream_id
        except RuntimeError as e:
            # We capture this here as there as nothing actually listens
            # for this finishing functions deferred.
            logger.warn(
                "TX [%s] Problem in _attempt_transaction: %s",
                destination,
                e,
            )

            success = False

            for p in pdus:
                logger.info("Failed to send event %s to %s", p.event_id, destination)
        except Exception as e:
            # We capture this here as there as nothing actually listens
            # for this finishing functions deferred.
            logger.warn(
                "TX [%s] Problem in _attempt_transaction: %s",
                destination,
                e,
            )

            success = False

            for p in pdus:
                logger.info("Failed to send event %s to %s", p.event_id, destination)

        defer.returnValue(success)
