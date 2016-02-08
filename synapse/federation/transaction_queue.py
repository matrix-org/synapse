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
from .units import Transaction

from synapse.api.errors import HttpResponseException
from synapse.util.logutils import log_function
from synapse.util.logcontext import PreserveLoggingContext
from synapse.util.retryutils import (
    get_retry_limiter, NotRetryingDestination,
)
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

        self._clock = hs.get_clock()

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

        # HACK to get unique tx id
        self._next_txn_id = int(self._clock.time_msec())

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

        deferreds = []

        for destination in destinations:
            deferred = defer.Deferred()
            self.pending_pdus_by_dest.setdefault(destination, []).append(
                (pdu, deferred, order)
            )

            def chain(failure):
                if not deferred.called:
                    deferred.errback(failure)

            def log_failure(f):
                logger.warn("Failed to send pdu to %s: %s", destination, f.value)

            deferred.addErrback(log_failure)

            with PreserveLoggingContext():
                self._attempt_new_transaction(destination).addErrback(chain)

            deferreds.append(deferred)

    # NO inlineCallbacks
    def enqueue_edu(self, edu):
        destination = edu.destination

        if not self.can_send_to(destination):
            return

        deferred = defer.Deferred()
        self.pending_edus_by_dest.setdefault(destination, []).append(
            (edu, deferred)
        )

        def chain(failure):
            if not deferred.called:
                deferred.errback(failure)

        def log_failure(f):
            logger.warn("Failed to send edu to %s: %s", destination, f.value)

        deferred.addErrback(log_failure)

        with PreserveLoggingContext():
            self._attempt_new_transaction(destination).addErrback(chain)

        return deferred

    @defer.inlineCallbacks
    def enqueue_failure(self, failure, destination):
        if destination == self.server_name or destination == "localhost":
            return

        deferred = defer.Deferred()

        if not self.can_send_to(destination):
            return

        self.pending_failures_by_dest.setdefault(
            destination, []
        ).append(
            (failure, deferred)
        )

        def chain(f):
            if not deferred.called:
                deferred.errback(f)

        def log_failure(f):
            logger.warn("Failed to send failure to %s: %s", destination, f.value)

        deferred.addErrback(log_failure)

        with PreserveLoggingContext():
            self._attempt_new_transaction(destination).addErrback(chain)

        yield deferred

    @defer.inlineCallbacks
    @log_function
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

        pending_pdus = self.pending_pdus_by_dest.pop(destination, [])
        pending_edus = self.pending_edus_by_dest.pop(destination, [])
        pending_failures = self.pending_failures_by_dest.pop(destination, [])

        if pending_pdus:
            logger.debug("TX [%s] len(pending_pdus_by_dest[dest]) = %d",
                         destination, len(pending_pdus))

        if not pending_pdus and not pending_edus and not pending_failures:
            logger.debug("TX [%s] Nothing to send", destination)
            return

        try:
            self.pending_transactions[destination] = 1

            logger.debug("TX [%s] _attempt_new_transaction", destination)

            # Sort based on the order field
            pending_pdus.sort(key=lambda t: t[2])

            pdus = [x[0] for x in pending_pdus]
            edus = [x[0] for x in pending_edus]
            failures = [x[0].get_dict() for x in pending_failures]
            deferreds = [
                x[1]
                for x in pending_pdus + pending_edus + pending_failures
            ]

            txn_id = str(self._next_txn_id)

            limiter = yield get_retry_limiter(
                destination,
                self._clock,
                self.store,
            )

            logger.debug(
                "TX [%s] {%s} Attempting new transaction"
                " (pdus: %d, edus: %d, failures: %d)",
                destination, txn_id,
                len(pending_pdus),
                len(pending_edus),
                len(pending_failures)
            )

            logger.debug("TX [%s] Persisting transaction...", destination)

            transaction = Transaction.create_new(
                origin_server_ts=int(self._clock.time_msec()),
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
                len(pending_pdus),
                len(pending_edus),
                len(pending_failures),
            )

            with limiter:
                # Actually send the transaction

                # FIXME (erikj): This is a bit of a hack to make the Pdu age
                # keys work
                def json_data_cb():
                    data = transaction.get_dict()
                    now = int(self._clock.time_msec())
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

            logger.debug("TX [%s] Yielding to callbacks...", destination)

            for deferred in deferreds:
                if code == 200:
                    deferred.callback(None)
                else:
                    deferred.errback(RuntimeError("Got status %d" % code))

                # Ensures we don't continue until all callbacks on that
                # deferred have fired
                try:
                    yield deferred
                except:
                    pass

            logger.debug("TX [%s] Yielded to callbacks", destination)
        except NotRetryingDestination:
            logger.info(
                "TX [%s] not ready for retry yet - "
                "dropping transaction for now",
                destination,
            )
        except RuntimeError as e:
            # We capture this here as there as nothing actually listens
            # for this finishing functions deferred.
            logger.warn(
                "TX [%s] Problem in _attempt_transaction: %s",
                destination,
                e,
            )
        except Exception as e:
            # We capture this here as there as nothing actually listens
            # for this finishing functions deferred.
            logger.warn(
                "TX [%s] Problem in _attempt_transaction: %s",
                destination,
                e,
            )

            for deferred in deferreds:
                if not deferred.called:
                    deferred.errback(e)

        finally:
            # We want to be *very* sure we delete this after we stop processing
            self.pending_transactions.pop(destination, None)

            # Check to see if there is anything else to send.
            self._attempt_new_transaction(destination)
