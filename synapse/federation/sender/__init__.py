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
"""
The Federation Sender is responsible for sending Persistent Data Units (PDUs)
and Ephemeral Data Units (EDUs) to other homeservers using
the `/send` Federation API.


## How do PDUs get sent?

The Federation Sender is made aware of new PDUs due to `FederationSender.notify_new_events`.
When the sender is notified about a newly-persisted PDU that originates from this homeserver
and is not an out-of-band event, we pass the PDU to the `_PerDestinationQueue` for each
remote homeserver that is in the room at that point in the DAG.


### Per-Destination Queues

There is one `PerDestinationQueue` per 'destination' homeserver.
The `PerDestinationQueue` maintains the following information about the destination:

- whether the destination is currently in [catch-up mode (see below)](#catch-up-mode);
- a queue of PDUs to be sent to the destination; and
- a queue of EDUs to be sent to the destination (not considered in this section).

Upon a new PDU being enqueued, `attempt_new_transaction` is called to start a new
transaction if there is not already one in progress.


### Transactions and the Transaction Transmission Loop

Each federation HTTP request to the `/send` endpoint is referred to as a 'transaction'.
The body of the HTTP request contains a list of PDUs and EDUs to send to the destination.

The *Transaction Transmission Loop* (`_transaction_transmission_loop`) is responsible
for emptying the queued PDUs (and EDUs) from a `PerDestinationQueue` by sending
them to the destination.

There can only be one transaction in flight for a given destination at any time.
(Other than preventing us from overloading the destination, this also makes it easier to
reason about because we process events sequentially for each destination.
This is useful for *Catch-Up Mode*, described later.)

The loop continues so long as there is anything to send. At each iteration of the loop, we:

- dequeue up to 50 PDUs (and up to 100 EDUs).
- make the `/send` request to the destination homeserver with the dequeued PDUs and EDUs.
- if successful, make note of the fact that we succeeded in transmitting PDUs up to
  the given `stream_ordering` of the latest PDU by
- if unsuccessful, back off from the remote homeserver for some time.
  If we have been unsuccessful for too long (when the backoff interval grows to exceed 1 hour),
  the in-memory queues are emptied and we enter [*Catch-Up Mode*, described below](#catch-up-mode).


### Catch-Up Mode

When the `PerDestinationQueue` has the catch-up flag set, the *Catch-Up Transmission Loop*
(`_catch_up_transmission_loop`) is used in lieu of the regular `_transaction_transmission_loop`.
(Only once the catch-up mode has been exited can the regular transaction transmission behaviour
be resumed.)

*Catch-Up Mode*, entered upon Synapse startup or once a homeserver has fallen behind due to
connection problems, is responsible for sending PDUs that have been missed by the destination
homeserver. (PDUs can be missed because the `PerDestinationQueue` is volatile — i.e. resets
on startup — and it does not hold PDUs forever if `/send` requests to the destination fail.)

The catch-up mechanism makes use of the `last_successful_stream_ordering` column in the
`destinations` table (which gives the `stream_ordering` of the most recent successfully
sent PDU) and the `stream_ordering` column in the `destination_rooms` table (which gives,
for each room, the `stream_ordering` of the most recent PDU that needs to be sent to this
destination).

Each iteration of the loop pulls out 50 `destination_rooms` entries with the oldest
`stream_ordering`s that are greater than the `last_successful_stream_ordering`.
In other words, from the set of latest PDUs in each room to be sent to the destination,
the 50 oldest such PDUs are pulled out.

These PDUs could, in principle, now be directly sent to the destination. However, as an
optimisation intended to prevent overloading destination homeservers, we instead attempt
to send the latest forward extremities so long as the destination homeserver is still
eligible to receive those.
This reduces load on the destination **in aggregate** because all Synapse homeservers
will behave according to this principle and therefore avoid sending lots of different PDUs
at different points in the DAG to a recovering homeserver.
*This optimisation is not currently valid in rooms which are partial-state on this homeserver,
since we are unable to determine whether the destination homeserver is eligible to receive
the latest forward extremities unless this homeserver sent those PDUs — in this case, we
just send the latest PDUs originating from this server and skip this optimisation.*

Whilst PDUs are sent through this mechanism, the position of `last_successful_stream_ordering`
is advanced as normal.
Once there are no longer any rooms containing outstanding PDUs to be sent to the destination
*that are not already in the `PerDestinationQueue` because they arrived since Catch-Up Mode
was enabled*, Catch-Up Mode is exited and we return to `_transaction_transmission_loop`.


#### A note on failures and back-offs

If a remote server is unreachable over federation, we back off from that server,
with an exponentially-increasing retry interval.
We automatically retry after the retry interval expires (roughly, the logic to do so
being triggered every minute).

If the backoff grows too large (> 1 hour), the in-memory queue is emptied (to prevent
unbounded growth) and Catch-Up Mode is entered.

It is worth noting that the back-off for a remote server is cleared once an inbound
request from that remote server is received (see `notify_remote_server_up`).
At this point, the transaction transmission loop is also started up, to proactively
send missed PDUs and EDUs to the destination (i.e. you don't need to wait for a new PDU
or EDU, destined for that destination, to be created in order to send out missed PDUs and
EDUs).
"""

import abc
import logging
from collections import OrderedDict
from typing import (
    TYPE_CHECKING,
    Collection,
    Dict,
    Hashable,
    Iterable,
    List,
    Optional,
    Set,
    Tuple,
)

import attr
from prometheus_client import Counter
from typing_extensions import Literal

from twisted.internet import defer

import synapse.metrics
from synapse.api.presence import UserPresenceState
from synapse.events import EventBase
from synapse.federation.sender.per_destination_queue import (
    CATCHUP_RETRY_INTERVAL,
    PerDestinationQueue,
)
from synapse.federation.sender.transaction_manager import TransactionManager
from synapse.federation.units import Edu
from synapse.logging.context import make_deferred_yieldable, run_in_background
from synapse.metrics import (
    LaterGauge,
    event_processing_loop_counter,
    event_processing_loop_room_count,
    events_processed_counter,
)
from synapse.metrics.background_process_metrics import (
    run_as_background_process,
    wrap_as_background_process,
)
from synapse.types import JsonDict, ReadReceipt, RoomStreamToken, StrCollection
from synapse.util import Clock
from synapse.util.metrics import Measure
from synapse.util.retryutils import filter_destinations_by_retry_limiter

if TYPE_CHECKING:
    from synapse.events.presence_router import PresenceRouter
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)

sent_pdus_destination_dist_count = Counter(
    "synapse_federation_client_sent_pdu_destinations_count",
    "Number of PDUs queued for sending to one or more destinations",
)

sent_pdus_destination_dist_total = Counter(
    "synapse_federation_client_sent_pdu_destinations",
    "Total number of PDUs queued for sending across all destinations",
)

# Time (in s) to wait before trying to wake up destinations that have
# catch-up outstanding. This will also be the delay applied at startup
# before trying the same.
# Please note that rate limiting still applies, so while the loop is
# executed every X seconds the destinations may not be wake up because
# they are being rate limited following previous attempt failures.
WAKEUP_RETRY_PERIOD_SEC = 60

# Time (in s) to wait in between waking up each destination, i.e. one destination
# will be woken up every <x> seconds until we have woken every destination
# has outstanding catch-up.
WAKEUP_INTERVAL_BETWEEN_DESTINATIONS_SEC = 5


class AbstractFederationSender(metaclass=abc.ABCMeta):
    @abc.abstractmethod
    def notify_new_events(self, max_token: RoomStreamToken) -> None:
        """This gets called when we have some new events we might want to
        send out to other servers.
        """
        raise NotImplementedError()

    @abc.abstractmethod
    async def send_read_receipt(self, receipt: ReadReceipt) -> None:
        """Send a RR to any other servers in the room

        Args:
            receipt: receipt to be sent
        """
        raise NotImplementedError()

    @abc.abstractmethod
    async def send_presence_to_destinations(
        self, states: Iterable[UserPresenceState], destinations: Iterable[str]
    ) -> None:
        """Send the given presence states to the given destinations.

        Args:
            destinations:
        """
        raise NotImplementedError()

    @abc.abstractmethod
    def build_and_send_edu(
        self,
        destination: str,
        edu_type: str,
        content: JsonDict,
        key: Optional[Hashable] = None,
    ) -> None:
        """Construct an Edu object, and queue it for sending

        Args:
            destination: name of server to send to
            edu_type: type of EDU to send
            content: content of EDU
            key: clobbering key for this edu
        """
        raise NotImplementedError()

    @abc.abstractmethod
    async def send_device_messages(
        self, destinations: StrCollection, immediate: bool = True
    ) -> None:
        """Tells the sender that a new device message is ready to be sent to the
        destinations. The `immediate` flag specifies whether the messages should
        be tried to be sent immediately, or whether it can be delayed for a
        short while (to aid performance).
        """
        raise NotImplementedError()

    @abc.abstractmethod
    def wake_destination(self, destination: str) -> None:
        """Called when we want to retry sending transactions to a remote.

        This is mainly useful if the remote server has been down and we think it
        might have come back.
        """
        raise NotImplementedError()

    @abc.abstractmethod
    def get_current_token(self) -> int:
        raise NotImplementedError()

    @abc.abstractmethod
    def federation_ack(self, instance_name: str, token: int) -> None:
        raise NotImplementedError()

    @abc.abstractmethod
    async def get_replication_rows(
        self, instance_name: str, from_token: int, to_token: int, target_row_count: int
    ) -> Tuple[List[Tuple[int, Tuple]], int, bool]:
        raise NotImplementedError()


@attr.s
class _DestinationWakeupQueue:
    """A queue of destinations that need to be woken up due to new updates.

    Staggers waking up of per destination queues to ensure that we don't attempt
    to start TLS connections with many hosts all at once, leading to pinned CPU.
    """

    # The maximum duration in seconds between queuing up a destination and it
    # being woken up.
    _MAX_TIME_IN_QUEUE = 30.0

    # The maximum duration in seconds between waking up consecutive destination
    # queues.
    _MAX_DELAY = 0.1

    sender: "FederationSender" = attr.ib()
    clock: Clock = attr.ib()
    queue: "OrderedDict[str, Literal[None]]" = attr.ib(factory=OrderedDict)
    processing: bool = attr.ib(default=False)

    def add_to_queue(self, destination: str) -> None:
        """Add a destination to the queue to be woken up."""

        self.queue[destination] = None

        if not self.processing:
            self._handle()

    @wrap_as_background_process("_DestinationWakeupQueue.handle")
    async def _handle(self) -> None:
        """Background process to drain the queue."""

        if not self.queue:
            return

        assert not self.processing
        self.processing = True

        try:
            # We start with a delay that should drain the queue quickly enough that
            # we process all destinations in the queue in _MAX_TIME_IN_QUEUE
            # seconds.
            #
            # We also add an upper bound to the delay, to gracefully handle the
            # case where the queue only has a few entries in it.
            current_sleep_seconds = min(
                self._MAX_DELAY, self._MAX_TIME_IN_QUEUE / len(self.queue)
            )

            while self.queue:
                destination, _ = self.queue.popitem(last=False)

                queue = self.sender._get_per_destination_queue(destination)

                if not queue._new_data_to_send:
                    # The per destination queue has already been woken up.
                    continue

                queue.attempt_new_transaction()

                await self.clock.sleep(current_sleep_seconds)

                if not self.queue:
                    break

                # More destinations may have been added to the queue, so we may
                # need to reduce the delay to ensure everything gets processed
                # within _MAX_TIME_IN_QUEUE seconds.
                current_sleep_seconds = min(
                    current_sleep_seconds, self._MAX_TIME_IN_QUEUE / len(self.queue)
                )

        finally:
            self.processing = False


class FederationSender(AbstractFederationSender):
    def __init__(self, hs: "HomeServer"):
        self.hs = hs
        self.server_name = hs.hostname

        self.store = hs.get_datastores().main
        self.state = hs.get_state_handler()

        self._storage_controllers = hs.get_storage_controllers()

        self.clock = hs.get_clock()
        self.is_mine_id = hs.is_mine_id
        self.is_mine_server_name = hs.is_mine_server_name

        self._presence_router: Optional["PresenceRouter"] = None
        self._transaction_manager = TransactionManager(hs)

        self._instance_name = hs.get_instance_name()
        self._federation_shard_config = hs.config.worker.federation_shard_config

        # map from destination to PerDestinationQueue
        self._per_destination_queues: Dict[str, PerDestinationQueue] = {}

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

        # map from room_id to a set of PerDestinationQueues which we believe are
        # awaiting a call to flush_read_receipts_for_room. The presence of an entry
        # here for a given room means that we are rate-limiting RR flushes to that room,
        # and that there is a pending call to _flush_rrs_for_room in the system.
        self._queues_awaiting_rr_flush_by_room: Dict[str, Set[PerDestinationQueue]] = {}

        self._rr_txn_interval_per_room_ms = (
            1000.0
            / hs.config.ratelimiting.federation_rr_transactions_per_room_per_second
        )

        # Regularly wake up destinations that have outstanding PDUs to be caught up
        self.clock.looping_call(
            run_as_background_process,
            WAKEUP_RETRY_PERIOD_SEC * 1000.0,
            "wake_destinations_needing_catchup",
            self._wake_destinations_needing_catchup,
        )

        self._external_cache = hs.get_external_cache()

        self._destination_wakeup_queue = _DestinationWakeupQueue(self, self.clock)

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
                (
                    next_token,
                    event_to_received_ts,
                ) = await self.store.get_all_new_event_ids_stream(
                    last_token, self._last_poked_id, limit=100
                )

                event_ids = event_to_received_ts.keys()
                event_entries = await self.store.get_unredacted_events_from_cache_or_db(
                    event_ids
                )

                logger.debug(
                    "Handling %i -> %i: %i events to send (current id %i)",
                    last_token,
                    next_token,
                    len(event_entries),
                    self._last_poked_id,
                )

                if not event_entries and next_token >= self._last_poked_id:
                    logger.debug("All events processed")
                    break

                async def handle_event(event: EventBase) -> None:
                    # Only send events for this server.
                    send_on_behalf_of = event.internal_metadata.get_send_on_behalf_of()
                    is_mine = self.is_mine_id(event.sender)
                    if not is_mine and send_on_behalf_of is None:
                        logger.debug("Not sending remote-origin event %s", event)
                        return

                    # We also want to not send out-of-band membership events.
                    #
                    # OOB memberships are used in three (and a half) situations:
                    #
                    # (1) invite events which we have received over federation. Those
                    #     will have a `sender` on a different server, so will be
                    #     skipped by the "is_mine" test above anyway.
                    #
                    # (2) rejections of invites to federated rooms - either remotely
                    #     or locally generated. (Such rejections are normally
                    #     created via federation, in which case the remote server is
                    #     responsible for sending out the rejection. If that fails,
                    #     we'll create a leave event locally, but that's only really
                    #     for the benefit of the invited user - we don't have enough
                    #     information to send it out over federation).
                    #
                    # (2a) rescinded knocks. These are identical to rejected invites.
                    #
                    # (3) knock events which we have sent over federation. As with
                    #     invite rejections, the remote server should send them out to
                    #     the federation.
                    #
                    # So, in all the above cases, we want to ignore such events.
                    #
                    # OOB memberships are always(?) outliers anyway, so if we *don't*
                    # ignore them, we'll get an exception further down when we try to
                    # fetch the membership list for the room.
                    #
                    # Arguably, we could equivalently ignore all outliers here, since
                    # in theory the only way for an outlier with a local `sender` to
                    # exist is by being an OOB membership (via one of (2), (2a) or (3)
                    # above).
                    #
                    if event.internal_metadata.is_out_of_band_membership():
                        logger.debug("Not sending OOB membership event %s", event)
                        return

                    # Finally, there are some other events that we should not send out
                    # until someone asks for them. They are explicitly flagged as such
                    # with `proactively_send: False`.
                    if not event.internal_metadata.should_proactively_send():
                        logger.debug(
                            "Not sending event with proactively_send=false: %s", event
                        )
                        return

                    destinations: Optional[Collection[str]] = None
                    if not event.prev_event_ids():
                        # If there are no prev event IDs then the state is empty
                        # and so no remote servers in the room
                        destinations = set()

                    if destinations is None:
                        # During partial join we use the set of servers that we got
                        # when beginning the join. It's still possible that we send
                        # events to servers that left the room in the meantime, but
                        # we consider that an acceptable risk since it is only our own
                        # events that we leak and not other server's ones.
                        partial_state_destinations = (
                            await self.store.get_partial_state_servers_at_join(
                                event.room_id
                            )
                        )

                        if partial_state_destinations is not None:
                            destinations = partial_state_destinations

                    if destinations is None:
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
                                # Add logging to help track down https://github.com/matrix-org/synapse/issues/13444
                                logger.info(
                                    "Unexpectedly did not have cached destinations for %s / %s",
                                    sg,
                                    event.event_id,
                                )
                        else:
                            # Add logging to help track down https://github.com/matrix-org/synapse/issues/13444
                            logger.info(
                                "Unexpectedly did not have cached prev group for %s",
                                event.event_id,
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

                    sharded_destinations = {
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
                        sharded_destinations.discard(send_on_behalf_of)

                    logger.debug("Sending %s to %r", event, sharded_destinations)

                    if sharded_destinations:
                        await self._send_pdu(event, sharded_destinations)

                        now = self.clock.time_msec()
                        ts = event_to_received_ts[event.event_id]
                        assert ts is not None
                        synapse.metrics.event_processing_lag_by_event.labels(
                            "federation_sender"
                        ).observe((now - ts) / 1000)

                async def handle_room_events(events: List[EventBase]) -> None:
                    logger.debug(
                        "Handling %i events in room %s", len(events), events[0].room_id
                    )
                    with Measure(self.clock, "handle_room_events"):
                        for event in events:
                            await handle_event(event)

                events_by_room: Dict[str, List[EventBase]] = {}

                for event_id in event_ids:
                    # `event_entries` is unsorted, so we have to iterate over `event_ids`
                    # to ensure the events are in the right order
                    event_cache = event_entries.get(event_id)
                    if event_cache:
                        event = event_cache.event
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

                logger.debug("Successfully handled up to %i", next_token)
                await self.store.update_federation_out_pos("events", next_token)

                if event_entries:
                    now = self.clock.time_msec()
                    ts = max(t for t in event_to_received_ts.values() if t)
                    assert ts is not None

                    synapse.metrics.event_processing_lag.labels(
                        "federation_sender"
                    ).set(now - ts)
                    synapse.metrics.event_processing_last_ts.labels(
                        "federation_sender"
                    ).set(ts)

                    events_processed_counter.inc(len(event_entries))

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

        destinations = await filter_destinations_by_retry_limiter(
            destinations,
            clock=self.clock,
            store=self.store,
            retry_due_within_ms=CATCHUP_RETRY_INTERVAL,
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
        domains_set = await self._storage_controllers.state.get_current_hosts_in_room_or_partial_state_approximation(
            room_id
        )
        domains: StrCollection = [
            d
            for d in domains_set
            if not self.is_mine_server_name(d)
            and self._federation_shard_config.should_handle(self._instance_name, d)
        ]

        domains = await filter_destinations_by_retry_limiter(
            domains,
            clock=self.clock,
            store=self.store,
            retry_due_within_ms=CATCHUP_RETRY_INTERVAL,
        )

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

    async def send_presence_to_destinations(
        self, states: Iterable[UserPresenceState], destinations: Iterable[str]
    ) -> None:
        """Send the given presence states to the given destinations.
        destinations (list[str])
        """

        if not states or not self.hs.config.server.track_presence:
            # No-op if presence is disabled.
            return

        # Ensure we only send out presence states for local users.
        for state in states:
            assert self.is_mine_id(state.user_id)

        destinations = await filter_destinations_by_retry_limiter(
            [
                d
                for d in destinations
                if self._federation_shard_config.should_handle(self._instance_name, d)
            ],
            clock=self.clock,
            store=self.store,
            retry_due_within_ms=CATCHUP_RETRY_INTERVAL,
        )

        for destination in destinations:
            if self.is_mine_server_name(destination):
                continue

            self._get_per_destination_queue(destination).send_presence(
                states, start_loop=False
            )

            self._destination_wakeup_queue.add_to_queue(destination)

    def build_and_send_edu(
        self,
        destination: str,
        edu_type: str,
        content: JsonDict,
        key: Optional[Hashable] = None,
    ) -> None:
        """Construct an Edu object, and queue it for sending

        Args:
            destination: name of server to send to
            edu_type: type of EDU to send
            content: content of EDU
            key: clobbering key for this edu
        """
        if self.is_mine_server_name(destination):
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

    def send_edu(self, edu: Edu, key: Optional[Hashable]) -> None:
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

    async def send_device_messages(
        self, destinations: StrCollection, immediate: bool = True
    ) -> None:
        destinations = await filter_destinations_by_retry_limiter(
            [
                destination
                for destination in destinations
                if self._federation_shard_config.should_handle(
                    self._instance_name, destination
                )
                and not self.is_mine_server_name(destination)
            ],
            clock=self.clock,
            store=self.store,
            retry_due_within_ms=CATCHUP_RETRY_INTERVAL,
        )

        for destination in destinations:
            if immediate:
                self._get_per_destination_queue(destination).attempt_new_transaction()
            else:
                self._get_per_destination_queue(destination).mark_new_data()
                self._destination_wakeup_queue.add_to_queue(destination)

    def wake_destination(self, destination: str) -> None:
        """Called when we want to retry sending transactions to a remote.

        This is mainly useful if the remote server has been down and we think it
        might have come back.
        """

        if self.is_mine_server_name(destination):
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

    def federation_ack(self, instance_name: str, token: int) -> None:
        # It is not expected that this gets called on FederationSender.
        raise NotImplementedError()

    @staticmethod
    async def get_replication_rows(
        instance_name: str, from_token: int, to_token: int, target_row_count: int
    ) -> Tuple[List[Tuple[int, Tuple]], int, bool]:
        # Dummy implementation for case where federation sender isn't offloaded
        # to a worker.
        return [], 0, False

    async def _wake_destinations_needing_catchup(self) -> None:
        """
        Wakes up destinations that need catch-up and are not currently being
        backed off from.

        In order to reduce load spikes, adds a delay between each destination.
        """

        last_processed: Optional[str] = None

        while True:
            destinations_to_wake = (
                await self.store.get_catch_up_outstanding_destinations(last_processed)
            )

            if not destinations_to_wake:
                # finished waking all destinations!
                break

            last_processed = destinations_to_wake[-1]

            destinations_to_wake = [
                d
                for d in destinations_to_wake
                if self._federation_shard_config.should_handle(self._instance_name, d)
            ]

            for destination in destinations_to_wake:
                logger.info(
                    "Destination %s has outstanding catch-up, waking up.",
                    last_processed,
                )
                self.wake_destination(destination)
                await self.clock.sleep(WAKEUP_INTERVAL_BETWEEN_DESTINATIONS_SEC)
