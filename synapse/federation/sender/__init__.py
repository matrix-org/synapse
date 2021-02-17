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
from typing import Dict, Hashable, Iterable, List, Optional, Set, Tuple

from prometheus_client import Counter

from twisted.internet import defer

import synapse
import synapse.metrics
from synapse.api.presence import UserPresenceState
from synapse.events import EventBase
from synapse.federation.sender.per_destination_queue import PerDestinationQueue
from synapse.federation.sender.transaction_manager import TransactionManager
from synapse.federation.units import Edu
from synapse.handlers.presence import get_interested_remotes
from synapse.logging.context import (
    make_deferred_yieldable,
    preserve_fn,
    run_in_background,
)
from synapse.metrics import (
    LaterGauge,
    event_processing_loop_counter,
    event_processing_loop_room_count,
    events_processed_counter,
)
from synapse.metrics.background_process_metrics import run_as_background_process
from synapse.types import ReadReceipt, RoomStreamToken
from synapse.util.metrics import Measure, measure_func

logger = logging.getLogger(__name__)

sent_pdus_destination_dist_count = Counter(
    "synapse_federation_client_sent_pdu_destinations:count",
    "Number of PDUs queued for sending to one or more destinations",
)

sent_pdus_destination_dist_total = Counter(
    "synapse_federation_client_sent_pdu_destinations:total",
    "Total number of PDUs queued for sending across all destinations",
)

# Time (in s) after Synapse's startup that we will begin to wake up destinations
# that have catch-up outstanding.
CATCH_UP_STARTUP_DELAY_SEC = 15

# Time (in s) to wait in between waking up each destination, i.e. one destination
# will be woken up every <x> seconds after Synapse's startup until we have woken
# every destination has outstanding catch-up.
CATCH_UP_STARTUP_INTERVAL_SEC = 5


class FederationSender:
    def __init__(self, hs: "synapse.server.HomeServer"):
        self.hs = hs
        self.server_name = hs.hostname

        self.store = hs.get_datastore()
        self.state = hs.get_state_handler()

        self.clock = hs.get_clock()
        self.is_mine_id = hs.is_mine_id

        self._transaction_manager = TransactionManager(hs)

        self._instance_name = hs.get_instance_name()
        self._federation_shard_config = hs.config.worker.federation_shard_config

        # map from destination to PerDestinationQueue
        self._per_destination_queues = {}  # type: Dict[str, PerDestinationQueue]

        LaterGauge(
            "synapse_federation_transaction_queue_pending_destinations",
            "",
            [],
            lambda: sum(
                1
                for d in self._per_destination_queues.values()
                if d.transmission_loop_running
            ),
        )

        # Map of user_id -> UserPresenceState for all the pending presence
        # to be sent out by user_id. Entries here get processed and put in
        # pending_presence_by_dest
        self.pending_presence = {}  # type: Dict[str, UserPresenceState]

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

        self._is_processing = False
        self._last_poked_id = -1

        self._processing_pending_presence = False

        # map from room_id to a set of PerDestinationQueues which we believe are
        # awaiting a call to flush_read_receipts_for_room. The presence of an entry
        # here for a given room means that we are rate-limiting RR flushes to that room,
        # and that there is a pending call to _flush_rrs_for_room in the system.
        self._queues_awaiting_rr_flush_by_room = (
            {}
        )  # type: Dict[str, Set[PerDestinationQueue]]

        self._rr_txn_interval_per_room_ms = (
            1000.0 / hs.config.federation_rr_transactions_per_room_per_second
        )

        # wake up destinations that have outstanding PDUs to be caught up
        self._catchup_after_startup_timer = self.clock.call_later(
            CATCH_UP_STARTUP_DELAY_SEC,
            run_as_background_process,
            "wake_destinations_needing_catchup",
            self._wake_destinations_needing_catchup,
        )

        self._external_cache = hs.get_external_cache()

    def _get_per_destination_queue(self, destination: str) -> PerDestinationQueue:
        """Get or create a PerDestinationQueue for the given destination

        Args:
            destination: server_name of remote server
        """
        queue = self._per_destination_queues.get(destination)
        if not queue:
            queue = PerDestinationQueue(self.hs, self._transaction_manager, destination)
            self._per_destination_queues[destination] = queue
        return queue

    def notify_new_events(self, max_token: RoomStreamToken) -> None:
        """This gets called when we have some new events we might want to
        send out to other servers.
        """
        # We just use the minimum stream ordering and ignore the vector clock
        # component. This is safe to do as long as we *always* ignore the vector
        # clock components.
        current_id = max_token.stream

        self._last_poked_id = max(current_id, self._last_poked_id)

        if self._is_processing:
            return

        # fire off a processing loop in the background
        run_as_background_process(
            "process_event_queue_for_federation", self._process_event_queue_loop
        )

    async def _process_event_queue_loop(self) -> None:
        try:
            self._is_processing = True
            while True:
                last_token = await self.store.get_federation_out_pos("events")
                next_token, events = await self.store.get_all_new_events_stream(
                    last_token, self._last_poked_id, limit=100
                )

                logger.debug("Handling %s -> %s", last_token, next_token)

                if not events and next_token >= self._last_poked_id:
                    break

                async def handle_event(event: EventBase) -> None:
                    # Only send events for this server.
                    send_on_behalf_of = event.internal_metadata.get_send_on_behalf_of()
                    is_mine = self.is_mine_id(event.sender)
                    if not is_mine and send_on_behalf_of is None:
                        return

                    if not event.internal_metadata.should_proactively_send():
                        return

                    destinations = None  # type: Optional[Set[str]]
                    if not event.prev_event_ids():
                        # If there are no prev event IDs then the state is empty
                        # and so no remote servers in the room
                        destinations = set()
                    else:
                        # We check the external cache for the destinations, which is
                        # stored per state group.

                        sg = await self._external_cache.get(
                            "event_to_prev_state_group", event.event_id
                        )
                        if sg:
                            destinations = await self._external_cache.get(
                                "get_joined_hosts", str(sg)
                            )

                    if destinations is None:
                        try:
                            # Get the state from before the event.
                            # We need to make sure that this is the state from before
                            # the event and not from after it.
                            # Otherwise if the last member on a server in a room is
                            # banned then it won't receive the event because it won't
                            # be in the room after the ban.
                            destinations = await self.state.get_hosts_in_room_at_events(
                                event.room_id, event_ids=event.prev_event_ids()
                            )
                        except Exception:
                            logger.exception(
                                "Failed to calculate hosts in room for event: %s",
                                event.event_id,
                            )
                            return

                    destinations = {
                        d
                        for d in destinations
                        if self._federation_shard_config.should_handle(
                            self._instance_name, d
                        )
                    }

                    if send_on_behalf_of is not None:
                        # If we are sending the event on behalf of another server
                        # then it already has the event and there is no reason to
                        # send the event to it.
                        destinations.discard(send_on_behalf_of)

                    logger.debug("Sending %s to %r", event, destinations)

                    if destinations:
                        await self._send_pdu(event, destinations)

                        now = self.clock.time_msec()
                        ts = await self.store.get_received_ts(event.event_id)

                        synapse.metrics.event_processing_lag_by_event.labels(
                            "federation_sender"
                        ).observe((now - ts) / 1000)

                async def handle_room_events(events: Iterable[EventBase]) -> None:
                    with Measure(self.clock, "handle_room_events"):
                        for event in events:
                            await handle_event(event)

                events_by_room = {}  # type: Dict[str, List[EventBase]]
                for event in events:
                    events_by_room.setdefault(event.room_id, []).append(event)

                await make_deferred_yieldable(
                    defer.gatherResults(
                        [
                            run_in_background(handle_room_events, evs)
                            for evs in events_by_room.values()
                        ],
                        consumeErrors=True,
                    )
                )

                await self.store.update_federation_out_pos("events", next_token)

                if events:
                    now = self.clock.time_msec()
                    ts = await self.store.get_received_ts(events[-1].event_id)

                    synapse.metrics.event_processing_lag.labels(
                        "federation_sender"
                    ).set(now - ts)
                    synapse.metrics.event_processing_last_ts.labels(
                        "federation_sender"
                    ).set(ts)

                    events_processed_counter.inc(len(events))

                    event_processing_loop_room_count.labels("federation_sender").inc(
                        len(events_by_room)
                    )

                event_processing_loop_counter.labels("federation_sender").inc()

                synapse.metrics.event_processing_positions.labels(
                    "federation_sender"
                ).set(next_token)

        finally:
            self._is_processing = False

    async def _send_pdu(self, pdu: EventBase, destinations: Iterable[str]) -> None:
        # We loop through all destinations to see whether we already have
        # a transaction in progress. If we do, stick it in the pending_pdus
        # table and we'll get back to it later.

        destinations = set(destinations)
        destinations.discard(self.server_name)
        logger.debug("Sending to: %s", str(destinations))

        if not destinations:
            return

        sent_pdus_destination_dist_total.inc(len(destinations))
        sent_pdus_destination_dist_count.inc()

        assert pdu.internal_metadata.stream_ordering

        # track the fact that we have a PDU for these destinations,
        # to allow us to perform catch-up later on if the remote is unreachable
        # for a while.
        await self.store.store_destination_rooms_entries(
            destinations,
            pdu.room_id,
            pdu.internal_metadata.stream_ordering,
        )

        for destination in destinations:
            self._get_per_destination_queue(destination).send_pdu(pdu)

    async def send_read_receipt(self, receipt: ReadReceipt) -> None:
        """Send a RR to any other servers in the room

        Args:
            receipt: receipt to be sent
        """

        # Some background on the rate-limiting going on here.
        #
        # It turns out that if we attempt to send out RRs as soon as we get them from
        # a client, then we end up trying to do several hundred Hz of federation
        # transactions. (The number of transactions scales as O(N^2) on the size of a
        # room, since in a large room we have both more RRs coming in, and more servers
        # to send them to.)
        #
        # This leads to a lot of CPU load, and we end up getting behind. The solution
        # currently adopted is as follows:
        #
        # The first receipt in a given room is sent out immediately, at time T0. Any
        # further receipts are, in theory, batched up for N seconds, where N is calculated
        # based on the number of servers in the room to achieve a transaction frequency
        # of around 50Hz. So, for example, if there were 100 servers in the room, then
        # N would be 100 / 50Hz = 2 seconds.
        #
        # Then, after T+N, we flush out any receipts that have accumulated, and restart
        # the timer to flush out more receipts at T+2N, etc. If no receipts accumulate,
        # we stop the cycle and go back to the start.
        #
        # However, in practice, it is often possible to flush out receipts earlier: in
        # particular, if we are sending a transaction to a given server anyway (for
        # example, because we have a PDU or a RR in another room to send), then we may
        # as well send out all of the pending RRs for that server. So it may be that
        # by the time we get to T+N, we don't actually have any RRs left to send out.
        # Nevertheless we continue to buffer up RRs for the room in question until we
        # reach the point that no RRs arrive between timer ticks.
        #
        # For even more background, see https://github.com/matrix-org/synapse/issues/4730.

        room_id = receipt.room_id

        # Work out which remote servers should be poked and poke them.
        domains_set = await self.state.get_current_hosts_in_room(room_id)
        domains = [
            d
            for d in domains_set
            if d != self.server_name
            and self._federation_shard_config.should_handle(self._instance_name, d)
        ]
        if not domains:
            return

        queues_pending_flush = self._queues_awaiting_rr_flush_by_room.get(room_id)

        # if there is no flush yet scheduled, we will send out these receipts with
        # immediate flushes, and schedule the next flush for this room.
        if queues_pending_flush is not None:
            logger.debug("Queuing receipt for: %r", domains)
        else:
            logger.debug("Sending receipt to: %r", domains)
            self._schedule_rr_flush_for_room(room_id, len(domains))

        for domain in domains:
            queue = self._get_per_destination_queue(domain)
            queue.queue_read_receipt(receipt)

            # if there is already a RR flush pending for this room, then make sure this
            # destination is registered for the flush
            if queues_pending_flush is not None:
                queues_pending_flush.add(queue)
            else:
                queue.flush_read_receipts_for_room(room_id)

    def _schedule_rr_flush_for_room(self, room_id: str, n_domains: int) -> None:
        # that is going to cause approximately len(domains) transactions, so now back
        # off for that multiplied by RR_TXN_INTERVAL_PER_ROOM
        backoff_ms = self._rr_txn_interval_per_room_ms * n_domains

        logger.debug("Scheduling RR flush in %s in %d ms", room_id, backoff_ms)
        self.clock.call_later(backoff_ms, self._flush_rrs_for_room, room_id)
        self._queues_awaiting_rr_flush_by_room[room_id] = set()

    def _flush_rrs_for_room(self, room_id: str) -> None:
        queues = self._queues_awaiting_rr_flush_by_room.pop(room_id)
        logger.debug("Flushing RRs in %s to %s", room_id, queues)

        if not queues:
            # no more RRs arrived for this room; we are done.
            return

        # schedule the next flush
        self._schedule_rr_flush_for_room(room_id, len(queues))

        for queue in queues:
            queue.flush_read_receipts_for_room(room_id)

    @preserve_fn  # the caller should not yield on this
    async def send_presence(self, states: List[UserPresenceState]):
        """Send the new presence states to the appropriate destinations.

        This actually queues up the presence states ready for sending and
        triggers a background task to process them and send out the transactions.
        """
        if not self.hs.config.use_presence:
            # No-op if presence is disabled.
            return

        # First we queue up the new presence by user ID, so multiple presence
        # updates in quick succession are correctly handled.
        # We only want to send presence for our own users, so lets always just
        # filter here just in case.
        self.pending_presence.update(
            {state.user_id: state for state in states if self.is_mine_id(state.user_id)}
        )

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

                await self._process_presence_inner(list(states_map.values()))
        except Exception:
            logger.exception("Error sending presence states to servers")
        finally:
            self._processing_pending_presence = False

    def send_presence_to_destinations(
        self, states: List[UserPresenceState], destinations: List[str]
    ) -> None:
        """Send the given presence states to the given destinations.
        destinations (list[str])
        """

        if not states or not self.hs.config.use_presence:
            # No-op if presence is disabled.
            return

        for destination in destinations:
            if destination == self.server_name:
                continue
            if not self._federation_shard_config.should_handle(
                self._instance_name, destination
            ):
                continue
            self._get_per_destination_queue(destination).send_presence(states)

    @measure_func("txnqueue._process_presence")
    async def _process_presence_inner(self, states: List[UserPresenceState]):
        """Given a list of states populate self.pending_presence_by_dest and
        poke to send a new transaction to each destination
        """
        hosts_and_states = await get_interested_remotes(self.store, states, self.state)

        for destinations, states in hosts_and_states:
            for destination in destinations:
                if destination == self.server_name:
                    continue

                if not self._federation_shard_config.should_handle(
                    self._instance_name, destination
                ):
                    continue

                self._get_per_destination_queue(destination).send_presence(states)

    def build_and_send_edu(
        self,
        destination: str,
        edu_type: str,
        content: dict,
        key: Optional[Hashable] = None,
    ):
        """Construct an Edu object, and queue it for sending

        Args:
            destination: name of server to send to
            edu_type: type of EDU to send
            content: content of EDU
            key: clobbering key for this edu
        """
        if destination == self.server_name:
            logger.info("Not sending EDU to ourselves")
            return

        if not self._federation_shard_config.should_handle(
            self._instance_name, destination
        ):
            return

        edu = Edu(
            origin=self.server_name,
            destination=destination,
            edu_type=edu_type,
            content=content,
        )

        self.send_edu(edu, key)

    def send_edu(self, edu: Edu, key: Optional[Hashable]):
        """Queue an EDU for sending

        Args:
            edu: edu to send
            key: clobbering key for this edu
        """
        if not self._federation_shard_config.should_handle(
            self._instance_name, edu.destination
        ):
            return

        queue = self._get_per_destination_queue(edu.destination)
        if key:
            queue.send_keyed_edu(edu, key)
        else:
            queue.send_edu(edu)

    def send_device_messages(self, destination: str):
        if destination == self.server_name:
            logger.warning("Not sending device update to ourselves")
            return

        if not self._federation_shard_config.should_handle(
            self._instance_name, destination
        ):
            return

        self._get_per_destination_queue(destination).attempt_new_transaction()

    def wake_destination(self, destination: str):
        """Called when we want to retry sending transactions to a remote.

        This is mainly useful if the remote server has been down and we think it
        might have come back.
        """

        if destination == self.server_name:
            logger.warning("Not waking up ourselves")
            return

        if not self._federation_shard_config.should_handle(
            self._instance_name, destination
        ):
            return

        self._get_per_destination_queue(destination).attempt_new_transaction()

    @staticmethod
    def get_current_token() -> int:
        # Dummy implementation for case where federation sender isn't offloaded
        # to a worker.
        return 0

    @staticmethod
    async def get_replication_rows(
        instance_name: str, from_token: int, to_token: int, target_row_count: int
    ) -> Tuple[List[Tuple[int, Tuple]], int, bool]:
        # Dummy implementation for case where federation sender isn't offloaded
        # to a worker.
        return [], 0, False

    async def _wake_destinations_needing_catchup(self):
        """
        Wakes up destinations that need catch-up and are not currently being
        backed off from.

        In order to reduce load spikes, adds a delay between each destination.
        """

        last_processed = None  # type: Optional[str]

        while True:
            destinations_to_wake = (
                await self.store.get_catch_up_outstanding_destinations(last_processed)
            )

            if not destinations_to_wake:
                # finished waking all destinations!
                self._catchup_after_startup_timer = None
                break

            destinations_to_wake = [
                d
                for d in destinations_to_wake
                if self._federation_shard_config.should_handle(self._instance_name, d)
            ]

            for last_processed in destinations_to_wake:
                logger.info(
                    "Destination %s has outstanding catch-up, waking up.",
                    last_processed,
                )
                self.wake_destination(last_processed)
                await self.clock.sleep(CATCH_UP_STARTUP_INTERVAL_SEC)
