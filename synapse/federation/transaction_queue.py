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
from synapse.types import get_domain_from_id
from synapse.handlers.presence import format_user_presence_state
import synapse.metrics

import logging


logger = logging.getLogger(__name__)

metrics = synapse.metrics.get_metrics_for(__name__)

client_metrics = synapse.metrics.get_metrics_for("synapse.federation.client")
sent_pdus_destination_dist = client_metrics.register_distribution(
    "sent_pdu_destinations"
)
sent_edus_counter = client_metrics.register_counter("sent_edus")


class TransactionQueue(object):
    """This class makes sure we only have one transaction in flight at
    a time for a given destination.

    It batches pending PDUs into single transactions.
    """

    def __init__(self, hs):
        self.server_name = hs.hostname

        self.store = hs.get_datastore()
        self.state = hs.get_state_handler()
        self.transaction_actions = TransactionActions(self.store)

        self.transport_layer = hs.get_federation_transport_client()

        self.clock = hs.get_clock()
        self.is_mine_id = hs.is_mine_id

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

        # Presence needs to be separate as we send single aggragate EDUs
        self.pending_presence_by_dest = presence = {}
        self.pending_edus_keyed_by_dest = edus_keyed = {}

        metrics.register_callback(
            "pending_pdus",
            lambda: sum(map(len, pdus.values())),
        )
        metrics.register_callback(
            "pending_edus",
            lambda: (
                sum(map(len, edus.values()))
                + sum(map(len, presence.values()))
                + sum(map(len, edus_keyed.values()))
            ),
        )

        # destination -> list of tuple(failure, deferred)
        self.pending_failures_by_dest = {}

        self.last_device_stream_id_by_dest = {}
        self.last_device_list_stream_id_by_dest = {}

        # HACK to get unique tx id
        self._next_txn_id = int(self.clock.time_msec())

        self._order = 1

        self._is_processing = False
        self._last_poked_id = -1

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

    @defer.inlineCallbacks
    def notify_new_events(self, current_id):
        """This gets called when we have some new events we might want to
        send out to other servers.
        """
        self._last_poked_id = max(current_id, self._last_poked_id)

        if self._is_processing:
            return

        try:
            self._is_processing = True
            while True:
                last_token = yield self.store.get_federation_out_pos("events")
                next_token, events = yield self.store.get_all_new_events_stream(
                    last_token, self._last_poked_id, limit=20,
                )

                logger.debug("Handling %s -> %s", last_token, next_token)

                if not events and next_token >= self._last_poked_id:
                    break

                for event in events:
                    # Only send events for this server.
                    send_on_behalf_of = event.internal_metadata.get_send_on_behalf_of()
                    is_mine = self.is_mine_id(event.event_id)
                    if not is_mine and send_on_behalf_of is None:
                        continue

                    # Get the state from before the event.
                    # We need to make sure that this is the state from before
                    # the event and not from after it.
                    # Otherwise if the last member on a server in a room is
                    # banned then it won't receive the event because it won't
                    # be in the room after the ban.
                    users_in_room = yield self.state.get_current_user_in_room(
                        event.room_id, latest_event_ids=[
                            prev_id for prev_id, _ in event.prev_events
                        ],
                    )

                    destinations = set(
                        get_domain_from_id(user_id) for user_id in users_in_room
                    )
                    if send_on_behalf_of is not None:
                        # If we are sending the event on behalf of another server
                        # then it already has the event and there is no reason to
                        # send the event to it.
                        destinations.discard(send_on_behalf_of)

                    logger.debug("Sending %s to %r", event, destinations)

                    self._send_pdu(event, destinations)

                yield self.store.update_federation_out_pos(
                    "events", next_token
                )

        finally:
            self._is_processing = False

    def _send_pdu(self, pdu, destinations):
        # We loop through all destinations to see whether we already have
        # a transaction in progress. If we do, stick it in the pending_pdus
        # table and we'll get back to it later.

        order = self._order
        self._order += 1

        destinations = set(destinations)
        destinations = set(
            dest for dest in destinations if self.can_send_to(dest)
        )

        logger.debug("Sending to: %s", str(destinations))

        if not destinations:
            return

        sent_pdus_destination_dist.inc_by(len(destinations))

        for destination in destinations:
            self.pending_pdus_by_dest.setdefault(destination, []).append(
                (pdu, order)
            )

            preserve_context_over_fn(
                self._attempt_new_transaction, destination
            )

    def send_presence(self, destination, states):
        if not self.can_send_to(destination):
            return

        self.pending_presence_by_dest.setdefault(destination, {}).update({
            state.user_id: state for state in states
        })

        preserve_context_over_fn(
            self._attempt_new_transaction, destination
        )

    def send_edu(self, destination, edu_type, content, key=None):
        edu = Edu(
            origin=self.server_name,
            destination=destination,
            edu_type=edu_type,
            content=content,
        )

        if not self.can_send_to(destination):
            return

        sent_edus_counter.inc()

        if key:
            self.pending_edus_keyed_by_dest.setdefault(
                destination, {}
            )[(edu.edu_type, key)] = edu
        else:
            self.pending_edus_by_dest.setdefault(destination, []).append(edu)

        preserve_context_over_fn(
            self._attempt_new_transaction, destination
        )

    def send_failure(self, failure, destination):
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

    def send_device_messages(self, destination):
        if destination == self.server_name or destination == "localhost":
            return

        if not self.can_send_to(destination):
            return

        preserve_context_over_fn(
            self._attempt_new_transaction, destination
        )

    def get_current_token(self):
        return 0

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
                pending_presence = self.pending_presence_by_dest.pop(destination, {})
                pending_failures = self.pending_failures_by_dest.pop(destination, [])

                pending_edus.extend(
                    self.pending_edus_keyed_by_dest.pop(destination, {}).values()
                )

                limiter = yield get_retry_limiter(
                    destination,
                    self.clock,
                    self.store,
                    backoff_on_404=True,  # If we get a 404 the other side has gone
                )

                device_message_edus, device_stream_id, dev_list_id = (
                    yield self._get_new_device_messages(destination)
                )

                pending_edus.extend(device_message_edus)
                if pending_presence:
                    pending_edus.append(
                        Edu(
                            origin=self.server_name,
                            destination=destination,
                            edu_type="m.presence",
                            content={
                                "push": [
                                    format_user_presence_state(
                                        presence, self.clock.time_msec()
                                    )
                                    for presence in pending_presence.values()
                                ]
                            },
                        )
                    )

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
                    limiter=limiter,
                )
                if success:
                    # Remove the acknowledged device messages from the database
                    # Only bother if we actually sent some device messages
                    if device_message_edus:
                        yield self.store.delete_device_msgs_for_remote(
                            destination, device_stream_id
                        )
                        logger.info("Marking as sent %r %r", destination, dev_list_id)
                        yield self.store.mark_as_sent_devices_by_remote(
                            destination, dev_list_id
                        )

                    self.last_device_stream_id_by_dest[destination] = device_stream_id
                    self.last_device_list_stream_id_by_dest[destination] = dev_list_id
                else:
                    break
        except NotRetryingDestination:
            logger.debug(
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

        last_device_list = self.last_device_list_stream_id_by_dest.get(destination, 0)
        now_stream_id, results = yield self.store.get_devices_by_remote(
            destination, last_device_list
        )
        edus.extend(
            Edu(
                origin=self.server_name,
                destination=destination,
                edu_type="m.device_list_update",
                content=content,
            )
            for content in results
        )
        defer.returnValue((edus, stream_id, now_stream_id))

    @measure_func("_send_new_transaction")
    @defer.inlineCallbacks
    def _send_new_transaction(self, destination, pending_pdus, pending_edus,
                              pending_failures, limiter):

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
