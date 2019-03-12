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
from synapse.api.errors import (
    FederationDeniedError,
    HttpResponseException,
    RequestSendFailed,
)
from synapse.events import EventBase
from synapse.handlers.presence import format_user_presence_state, get_interested_remotes
from synapse.metrics import (
    LaterGauge,
    event_processing_loop_counter,
    event_processing_loop_room_count,
    events_processed_counter,
    sent_transactions_counter,
)
from synapse.metrics.background_process_metrics import run_as_background_process
from synapse.storage import UserPresenceState
from synapse.util import logcontext
from synapse.util.metrics import measure_func
from synapse.util.retryutils import NotRetryingDestination, get_retry_limiter

from .persistence import TransactionActions
from .units import Edu, Transaction

logger = logging.getLogger(__name__)

sent_pdus_destination_dist_count = Counter(
    "synapse_federation_client_sent_pdu_destinations:count",
    "Number of PDUs queued for sending to one or more destinations",
)

sent_pdus_destination_dist_total = Counter(
    "synapse_federation_client_sent_pdu_destinations:total", ""
    "Total number of PDUs queued for sending across all destinations",
)

sent_edus_counter = Counter(
    "synapse_federation_client_sent_edus",
    "Total number of EDUs successfully sent",
)

sent_edus_by_type = Counter(
    "synapse_federation_client_sent_edus_by_type",
    "Number of sent EDUs successfully sent, by event type",
    ["type"],
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

        self.clock = hs.get_clock()
        self.is_mine_id = hs.is_mine_id

        self._transaction_sender = TransactionSender(hs)

        # map from destination to PerDestinationQueue
        self._per_destination_queues = {}   # type: dict[str, PerDestinationQueue]

        LaterGauge(
            "synapse_federation_transaction_queue_pending_destinations",
            "",
            [],
            lambda: sum(
                1 for d in self._per_destination_queues.values()
                if d.transmission_loop_running
            ),
        )

        # Map of user_id -> UserPresenceState for all the pending presence
        # to be sent out by user_id. Entries here get processed and put in
        # pending_presence_by_dest
        self.pending_presence = {}

        LaterGauge(
            "synapse_federation_transaction_queue_pending_pdus",
            "",
            [],
            lambda: sum(
                d.pending_pdu_count() for d in self._per_destination_queues.values()
            ),
        )
        LaterGauge(
            "synapse_federation_transaction_queue_pending_edus",
            "",
            [],
            lambda: sum(
                d.pending_edu_count() for d in self._per_destination_queues.values()
            ),
        )

        self._order = 1

        self._is_processing = False
        self._last_poked_id = -1

        self._processing_pending_presence = False

    def _get_per_destination_queue(self, destination):
        queue = self._per_destination_queues.get(destination)
        if not queue:
            queue = PerDestinationQueue(self.hs, self._transaction_sender, destination)
            self._per_destination_queues[destination] = queue
        return queue

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
                    is_mine = self.is_mine_id(event.sender)
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
                            event.room_id, latest_event_ids=event.prev_event_ids(),
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
        destinations.discard(self.server_name)
        logger.debug("Sending to: %s", str(destinations))

        if not destinations:
            return

        sent_pdus_destination_dist_total.inc(len(destinations))
        sent_pdus_destination_dist_count.inc()

        for destination in destinations:
            self._get_per_destination_queue(destination).send_pdu(pdu, order)

    @defer.inlineCallbacks
    def send_read_receipt(self, receipt):
        """Send a RR to any other servers in the room

        Args:
            receipt (synapse.types.ReadReceipt): receipt to be sent
        """
        # Work out which remote servers should be poked and poke them.
        domains = yield self.state.get_current_hosts_in_room(receipt.room_id)
        domains = [d for d in domains if d != self.server_name]
        if not domains:
            return

        logger.debug("Sending receipt to: %r", domains)

        content = {
            receipt.room_id: {
                receipt.receipt_type: {
                    receipt.user_id: {
                        "event_ids": receipt.event_ids,
                        "data": receipt.data,
                    },
                },
            },
        }
        key = (receipt.room_id, receipt.receipt_type, receipt.user_id)

        for domain in domains:
            self.build_and_send_edu(
                destination=domain,
                edu_type="m.receipt",
                content=content,
                key=key,
            )

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
                if destination == self.server_name:
                    continue
                self._get_per_destination_queue(destination).send_presence(states)

    def build_and_send_edu(self, destination, edu_type, content, key=None):
        """Construct an Edu object, and queue it for sending

        Args:
            destination (str): name of server to send to
            edu_type (str): type of EDU to send
            content (dict): content of EDU
            key (Any|None): clobbering key for this edu
        """
        if destination == self.server_name:
            logger.info("Not sending EDU to ourselves")
            return

        edu = Edu(
            origin=self.server_name,
            destination=destination,
            edu_type=edu_type,
            content=content,
        )

        self.send_edu(edu, key)

    def send_edu(self, edu, key):
        """Queue an EDU for sending

        Args:
            edu (Edu): edu to send
            key (Any|None): clobbering key for this edu
        """
        queue = self._get_per_destination_queue(edu.destination)
        if key:
            queue.send_keyed_edu(edu, key)
        else:
            queue.send_edu(edu)

    def send_device_messages(self, destination):
        if destination == self.server_name:
            logger.info("Not sending device update to ourselves")
            return

        self._get_per_destination_queue(destination).attempt_new_transaction()

    def get_current_token(self):
        return 0


class PerDestinationQueue(object):
    """
    Manages the per-destination transmission queues.
    """
    def __init__(self, hs, transaction_sender, destination):
        self._server_name = hs.hostname
        self._clock = hs.get_clock()
        self._store = hs.get_datastore()
        self._transaction_sender = transaction_sender

        self._destination = destination
        self.transmission_loop_running = False

        # a list of tuples of (pending pdu, order)
        self._pending_pdus = []    # type: list[tuple[EventBase, int]]
        self._pending_edus = []    # type: list[Edu]

        # Pending EDUs by their "key". Keyed EDUs are EDUs that get clobbered
        # based on their key (e.g. typing events by room_id)
        # Map of (edu_type, key) -> Edu
        self._pending_edus_keyed = {}   # type: dict[tuple[str, str], Edu]

        # Map of user_id -> UserPresenceState of pending presence to be sent to this
        # destination
        self._pending_presence = {}   # type: dict[str, UserPresenceState]

        # stream_id of last successfully sent to-device message.
        # NB: may be a long or an int.
        self._last_device_stream_id = 0

        # stream_id of last successfully sent device list update.
        self._last_device_list_stream_id = 0

    def pending_pdu_count(self):
        return len(self._pending_pdus)

    def pending_edu_count(self):
        return (
            len(self._pending_edus)
            + len(self._pending_presence)
            + len(self._pending_edus_keyed)
        )

    def send_pdu(self, pdu, order):
        """Add a PDU to the queue, and start the transmission loop if neccessary

        Args:
            pdu (EventBase): pdu to send
            order (int):
        """
        self._pending_pdus.append((pdu, order))
        self.attempt_new_transaction()

    def send_presence(self, states):
        """Add presence updates to the queue. Start the transmission loop if neccessary.

        Args:
            states (iterable[UserPresenceState]): presence to send
        """
        self._pending_presence.update({
            state.user_id: state for state in states
        })
        self.attempt_new_transaction()

    def send_keyed_edu(self, edu, key):
        self._pending_edus_keyed[(edu.edu_type, key)] = edu
        self.attempt_new_transaction()

    def send_edu(self, edu):
        self._pending_edus.append(edu)
        self.attempt_new_transaction()

    def attempt_new_transaction(self):
        """Try to start a new transaction to this destination

        If there is already a transaction in progress to this destination,
        returns immediately. Otherwise kicks off the process of sending a
        transaction in the background.
        """
        # list of (pending_pdu, deferred, order)
        if self.transmission_loop_running:
            # XXX: this can get stuck on by a never-ending
            # request at which point pending_pdus just keeps growing.
            # we need application-layer timeouts of some flavour of these
            # requests
            logger.debug(
                "TX [%s] Transaction already in progress",
                self._destination
            )
            return

        logger.debug("TX [%s] Starting transaction loop", self._destination)

        run_as_background_process(
            "federation_transaction_transmission_loop",
            self._transaction_transmission_loop,
        )

    @defer.inlineCallbacks
    def _transaction_transmission_loop(self):
        pending_pdus = []
        try:
            self.transmission_loop_running = True

            # This will throw if we wouldn't retry. We do this here so we fail
            # quickly, but we will later check this again in the http client,
            # hence why we throw the result away.
            yield get_retry_limiter(self._destination, self._clock, self._store)

            pending_pdus = []
            while True:
                device_message_edus, device_stream_id, dev_list_id = (
                    yield self._get_new_device_messages()
                )

                # BEGIN CRITICAL SECTION
                #
                # In order to avoid a race condition, we need to make sure that
                # the following code (from popping the queues up to the point
                # where we decide if we actually have any pending messages) is
                # atomic - otherwise new PDUs or EDUs might arrive in the
                # meantime, but not get sent because we hold the
                # transmission_loop_running flag.

                pending_pdus = self._pending_pdus

                # We can only include at most 50 PDUs per transactions
                pending_pdus, self._pending_pdus = pending_pdus[:50], pending_pdus[50:]

                pending_edus = self._pending_edus

                # We can only include at most 100 EDUs per transactions
                pending_edus, self._pending_edus = pending_edus[:100], pending_edus[100:]

                pending_edus.extend(
                    self._pending_edus_keyed.values()
                )

                self._pending_edus_keyed = {}

                pending_edus.extend(device_message_edus)

                pending_presence = self._pending_presence
                self._pending_presence = {}
                if pending_presence:
                    pending_edus.append(
                        Edu(
                            origin=self._server_name,
                            destination=self._destination,
                            edu_type="m.presence",
                            content={
                                "push": [
                                    format_user_presence_state(
                                        presence, self._clock.time_msec()
                                    )
                                    for presence in pending_presence.values()
                                ]
                            },
                        )
                    )

                if pending_pdus:
                    logger.debug("TX [%s] len(pending_pdus_by_dest[dest]) = %d",
                                 self._destination, len(pending_pdus))

                if not pending_pdus and not pending_edus:
                    logger.debug("TX [%s] Nothing to send", self._destination)
                    self._last_device_stream_id = device_stream_id
                    return

                # END CRITICAL SECTION

                success = yield self._transaction_sender.send_new_transaction(
                    self._destination, pending_pdus, pending_edus
                )
                if success:
                    sent_transactions_counter.inc()
                    sent_edus_counter.inc(len(pending_edus))
                    for edu in pending_edus:
                        sent_edus_by_type.labels(edu.edu_type).inc()
                    # Remove the acknowledged device messages from the database
                    # Only bother if we actually sent some device messages
                    if device_message_edus:
                        yield self._store.delete_device_msgs_for_remote(
                            self._destination, device_stream_id
                        )
                        logger.info(
                            "Marking as sent %r %r", self._destination, dev_list_id
                        )
                        yield self._store.mark_as_sent_devices_by_remote(
                            self._destination, dev_list_id
                        )

                    self._last_device_stream_id = device_stream_id
                    self._last_device_list_stream_id = dev_list_id
                else:
                    break
        except NotRetryingDestination as e:
            logger.debug(
                "TX [%s] not ready for retry yet (next retry at %s) - "
                "dropping transaction for now",
                self._destination,
                datetime.datetime.fromtimestamp(
                    (e.retry_last_ts + e.retry_interval) / 1000.0
                ),
            )
        except FederationDeniedError as e:
            logger.info(e)
        except HttpResponseException as e:
            logger.warning(
                "TX [%s] Received %d response to transaction: %s",
                self._destination, e.code, e,
            )
        except RequestSendFailed as e:
            logger.warning("TX [%s] Failed to send transaction: %s", self._destination, e)

            for p, _ in pending_pdus:
                logger.info("Failed to send event %s to %s", p.event_id,
                            self._destination)
        except Exception:
            logger.exception(
                "TX [%s] Failed to send transaction",
                self._destination,
            )
            for p, _ in pending_pdus:
                logger.info("Failed to send event %s to %s", p.event_id,
                            self._destination)
        finally:
            # We want to be *very* sure we clear this after we stop processing
            self.transmission_loop_running = False

    @defer.inlineCallbacks
    def _get_new_device_messages(self):
        last_device_stream_id = self._last_device_stream_id
        to_device_stream_id = self._store.get_to_device_stream_token()
        contents, stream_id = yield self._store.get_new_device_msgs_for_remote(
            self._destination, last_device_stream_id, to_device_stream_id
        )
        edus = [
            Edu(
                origin=self._server_name,
                destination=self._destination,
                edu_type="m.direct_to_device",
                content=content,
            )
            for content in contents
        ]

        last_device_list = self._last_device_list_stream_id
        now_stream_id, results = yield self._store.get_devices_by_remote(
            self._destination, last_device_list
        )
        edus.extend(
            Edu(
                origin=self._server_name,
                destination=self._destination,
                edu_type="m.device_list_update",
                content=content,
            )
            for content in results
        )
        defer.returnValue((edus, stream_id, now_stream_id))


class TransactionSender(object):
    """Helper class which handles building and sending transactions

    shared between PerDestinationQueue objects
    """
    def __init__(self, hs):
        self._server_name = hs.hostname
        self._clock = hs.get_clock()
        self._store = hs.get_datastore()
        self._transaction_actions = TransactionActions(self._store)
        self._transport_layer = hs.get_federation_transport_client()

        # HACK to get unique tx id
        self._next_txn_id = int(self._clock.time_msec())

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
            origin_server_ts=int(self._clock.time_msec()),
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
            now = int(self._clock.time_msec())
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
