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
import datetime
import logging

from six import itervalues

from prometheus_client import Counter

from twisted.internet import defer

import synapse.metrics
from synapse.api.errors import FederationDeniedError, HttpResponseException
from synapse.handlers.presence import format_user_presence_state, get_interested_remotes
from synapse.metrics import (
    LaterGauge,
    event_processing_loop_counter,
    event_processing_loop_room_count,
    events_processed_counter,
    sent_edus_counter,
    sent_transactions_counter,
)
from synapse.metrics.background_process_metrics import run_as_background_process
from synapse.util import logcontext
from synapse.util.metrics import measure_func
from synapse.util.retryutils import NotRetryingDestination, get_retry_limiter

from .persistence import TransactionActions
from .units import Edu, Transaction

logger = logging.getLogger(__name__)

sent_pdus_destination_dist_count = Counter(
    "synapse_federation_client_sent_pdu_destinations:count", ""
)
sent_pdus_destination_dist_total = Counter(
    "synapse_federation_client_sent_pdu_destinations:total", ""
)


class TransactionQueue(object):
    """This class makes sure we only have one transaction in flight at
    a time for a given destination.

    It batches pending PDUs into single transactions.
    """

    def __init__(self, hs):
        self.hs = hs
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

        LaterGauge(
            "synapse_federation_transaction_queue_pending_destinations",
            "",
            [],
            lambda: len(self.pending_transactions),
        )

        # Is a mapping from destination -> list of
        # tuple(pending pdus, deferred, order)
        self.pending_pdus_by_dest = pdus = {}
        # destination -> list of tuple(edu, deferred)
        self.pending_edus_by_dest = edus = {}

        # Map of user_id -> UserPresenceState for all the pending presence
        # to be sent out by user_id. Entries here get processed and put in
        # pending_presence_by_dest
        self.pending_presence = {}

        # Map of destination -> user_id -> UserPresenceState of pending presence
        # to be sent to each destinations
        self.pending_presence_by_dest = presence = {}

        # Pending EDUs by their "key". Keyed EDUs are EDUs that get clobbered
        # based on their key (e.g. typing events by room_id)
        # Map of destination -> (edu_type, key) -> Edu
        self.pending_edus_keyed_by_dest = edus_keyed = {}

        LaterGauge(
            "synapse_federation_transaction_queue_pending_pdus",
            "",
            [],
            lambda: sum(map(len, pdus.values())),
        )
        LaterGauge(
            "synapse_federation_transaction_queue_pending_edus",
            "",
            [],
            lambda: (
                sum(map(len, edus.values()))
                + sum(map(len, presence.values()))
                + sum(map(len, edus_keyed.values()))
            ),
        )

        # destination -> stream_id of last successfully sent to-device message.
        # NB: may be a long or an int.
        self.last_device_stream_id_by_dest = {}

        # destination -> stream_id of last successfully sent device list
        # update.
        self.last_device_list_stream_id_by_dest = {}

        # HACK to get unique tx id
        self._next_txn_id = int(self.clock.time_msec())

        self._order = 1

        self._is_processing = False
        self._last_poked_id = -1

        self._processing_pending_presence = False

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

    def notify_new_events(self, current_id):
        """This gets called when we have some new events we might want to
        send out to other servers.
        """
        self._last_poked_id = max(current_id, self._last_poked_id)

        if self._is_processing:
            return

        # fire off a processing loop in the background
        run_as_background_process(
            "process_event_queue_for_federation",
            self._process_event_queue_loop,
        )

    @defer.inlineCallbacks
    def _process_event_queue_loop(self):
        try:
            self._is_processing = True
            while True:
                last_token = yield self.store.get_federation_out_pos("events")
                next_token, events = yield self.store.get_all_new_events_stream(
                    last_token, self._last_poked_id, limit=100,
                )

                logger.debug("Handling %s -> %s", last_token, next_token)

                if not events and next_token >= self._last_poked_id:
                    break

                @defer.inlineCallbacks
                def handle_event(event):
                    # Only send events for this server.
                    send_on_behalf_of = event.internal_metadata.get_send_on_behalf_of()
                    is_mine = self.is_mine_id(event.event_id)
                    if not is_mine and send_on_behalf_of is None:
                        return

                    try:
                        # Get the state from before the event.
                        # We need to make sure that this is the state from before
                        # the event and not from after it.
                        # Otherwise if the last member on a server in a room is
                        # banned then it won't receive the event because it won't
                        # be in the room after the ban.
                        destinations = yield self.state.get_current_hosts_in_room(
                            event.room_id, latest_event_ids=[
                                prev_id for prev_id, _ in event.prev_events
                            ],
                        )
                    except Exception:
                        logger.exception(
                            "Failed to calculate hosts in room for event: %s",
                            event.event_id,
                        )
                        return

                    destinations = set(destinations)

                    if send_on_behalf_of is not None:
                        # If we are sending the event on behalf of another server
                        # then it already has the event and there is no reason to
                        # send the event to it.
                        destinations.discard(send_on_behalf_of)

                    logger.debug("Sending %s to %r", event, destinations)

                    self._send_pdu(event, destinations)

                @defer.inlineCallbacks
                def handle_room_events(events):
                    for event in events:
                        yield handle_event(event)

                events_by_room = {}
                for event in events:
                    events_by_room.setdefault(event.room_id, []).append(event)

                yield logcontext.make_deferred_yieldable(defer.gatherResults(
                    [
                        logcontext.run_in_background(handle_room_events, evs)
                        for evs in itervalues(events_by_room)
                    ],
                    consumeErrors=True
                ))

                yield self.store.update_federation_out_pos(
                    "events", next_token
                )

                if events:
                    now = self.clock.time_msec()
                    ts = yield self.store.get_received_ts(events[-1].event_id)

                    synapse.metrics.event_processing_lag.labels(
                        "federation_sender").set(now - ts)
                    synapse.metrics.event_processing_last_ts.labels(
                        "federation_sender").set(ts)

                    events_processed_counter.inc(len(events))

                    event_processing_loop_room_count.labels(
                        "federation_sender"
                    ).inc(len(events_by_room))

                event_processing_loop_counter.labels("federation_sender").inc()

                synapse.metrics.event_processing_positions.labels(
                    "federation_sender").set(next_token)

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

        sent_pdus_destination_dist_total.inc(len(destinations))
        sent_pdus_destination_dist_count.inc()

        for destination in destinations:
            self.pending_pdus_by_dest.setdefault(destination, []).append(
                (pdu, order)
            )

            self._attempt_new_transaction(destination)

    @logcontext.preserve_fn  # the caller should not yield on this
    @defer.inlineCallbacks
    def send_presence(self, states):
        """Send the new presence states to the appropriate destinations.

        This actually queues up the presence states ready for sending and
        triggers a background task to process them and send out the transactions.

        Args:
            states (list(UserPresenceState))
        """
        if not self.hs.config.use_presence:
            # No-op if presence is disabled.
            return

        # First we queue up the new presence by user ID, so multiple presence
        # updates in quick successtion are correctly handled
        # We only want to send presence for our own users, so lets always just
        # filter here just in case.
        self.pending_presence.update({
            state.user_id: state for state in states
            if self.is_mine_id(state.user_id)
        })

        # We then handle the new pending presence in batches, first figuring
        # out the destinations we need to send each state to and then poking it
        # to attempt a new transaction. We linearize this so that we don't
        # accidentally mess up the ordering and send multiple presence updates
        # in the wrong order
        if self._processing_pending_presence:
            return

        self._processing_pending_presence = True
        try:
            while True:
                states_map = self.pending_presence
                self.pending_presence = {}

                if not states_map:
                    break

                yield self._process_presence_inner(list(states_map.values()))
        except Exception:
            logger.exception("Error sending presence states to servers")
        finally:
            self._processing_pending_presence = False

    @measure_func("txnqueue._process_presence")
    @defer.inlineCallbacks
    def _process_presence_inner(self, states):
        """Given a list of states populate self.pending_presence_by_dest and
        poke to send a new transaction to each destination

        Args:
            states (list(UserPresenceState))
        """
        hosts_and_states = yield get_interested_remotes(self.store, states, self.state)

        for destinations, states in hosts_and_states:
            for destination in destinations:
                if not self.can_send_to(destination):
                    continue

                self.pending_presence_by_dest.setdefault(
                    destination, {}
                ).update({
                    state.user_id: state for state in states
                })

                self._attempt_new_transaction(destination)

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

        self._attempt_new_transaction(destination)

    def send_device_messages(self, destination):
        if destination == self.server_name or destination == "localhost":
            return

        if not self.can_send_to(destination):
            return

        self._attempt_new_transaction(destination)

    def get_current_token(self):
        return 0

    def _attempt_new_transaction(self, destination):
        """Try to start a new transaction to this destination

        If there is already a transaction in progress to this destination,
        returns immediately. Otherwise kicks off the process of sending a
        transaction in the background.

        Args:
            destination (str):

        Returns:
            None
        """
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

        logger.debug("TX [%s] Starting transaction loop", destination)

        run_as_background_process(
            "federation_transaction_transmission_loop",
            self._transaction_transmission_loop,
            destination,
        )

    @defer.inlineCallbacks
    def _transaction_transmission_loop(self, destination):
        pending_pdus = []
        try:
            self.pending_transactions[destination] = 1

            # This will throw if we wouldn't retry. We do this here so we fail
            # quickly, but we will later check this again in the http client,
            # hence why we throw the result away.
            yield get_retry_limiter(destination, self.clock, self.store)

            pending_pdus = []
            while True:
                device_message_edus, device_stream_id, dev_list_id = (
                    yield self._get_new_device_messages(destination)
                )

                # BEGIN CRITICAL SECTION
                #
                # In order to avoid a race condition, we need to make sure that
                # the following code (from popping the queues up to the point
                # where we decide if we actually have any pending messages) is
                # atomic - otherwise new PDUs or EDUs might arrive in the
                # meantime, but not get sent because we hold the
                # pending_transactions flag.

                pending_pdus = self.pending_pdus_by_dest.pop(destination, [])

                # We can only include at most 50 PDUs per transactions
                pending_pdus, leftover_pdus = pending_pdus[:50], pending_pdus[50:]
                if leftover_pdus:
                    self.pending_pdus_by_dest[destination] = leftover_pdus

                pending_edus = self.pending_edus_by_dest.pop(destination, [])

                # We can only include at most 100 EDUs per transactions
                pending_edus, leftover_edus = pending_edus[:100], pending_edus[100:]
                if leftover_edus:
                    self.pending_edus_by_dest[destination] = leftover_edus

                pending_presence = self.pending_presence_by_dest.pop(destination, {})

                pending_edus.extend(
                    self.pending_edus_keyed_by_dest.pop(destination, {}).values()
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

                if not pending_pdus and not pending_edus:
                    logger.debug("TX [%s] Nothing to send", destination)
                    self.last_device_stream_id_by_dest[destination] = (
                        device_stream_id
                    )
                    return

                # END CRITICAL SECTION

                success = yield self._send_new_transaction(
                    destination, pending_pdus, pending_edus,
                )
                if success:
                    sent_transactions_counter.inc()
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
        except NotRetryingDestination as e:
            logger.debug(
                "TX [%s] not ready for retry yet (next retry at %s) - "
                "dropping transaction for now",
                destination,
                datetime.datetime.fromtimestamp(
                    (e.retry_last_ts + e.retry_interval) / 1000.0
                ),
            )
        except FederationDeniedError as e:
            logger.info(e)
        except Exception as e:
            logger.warn(
                "TX [%s] Failed to send transaction: %s",
                destination,
                e,
            )
            for p, _ in pending_pdus:
                logger.info("Failed to send event %s to %s", p.event_id,
                            destination)
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
    def _send_new_transaction(self, destination, pending_pdus, pending_edus):

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
            origin=self.server_name,
            destination=destination,
            pdus=pdus,
            edus=edus,
        )

        self._next_txn_id += 1

        yield self.transaction_actions.prepare_to_send(transaction)

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

        defer.returnValue(success)
