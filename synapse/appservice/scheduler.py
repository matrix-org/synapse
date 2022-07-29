# Copyright 2015, 2016 OpenMarket Ltd
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
This module controls the reliability for application service transactions.

The nominal flow through this module looks like:
              __________
1---ASa[e]-->|  Service |--> Queue ASa[f]
2----ASb[e]->|  Queuer  |
3--ASa[f]--->|__________|-----------+ ASa[e], ASb[e]
                                    V
      -````````-            +------------+
      |````````|<--StoreTxn-|Transaction |
      |Database|            | Controller |---> SEND TO AS
      `--------`            +------------+
What happens on SEND TO AS depends on the state of the Application Service:
 - If the AS is marked as DOWN, do nothing.
 - If the AS is marked as UP, send the transaction.
     * SUCCESS : Increment where the AS is up to txn-wise and nuke the txn
                 contents from the db.
     * FAILURE : Marked AS as DOWN and start Recoverer.

Recoverer attempts to recover ASes who have died. The flow for this looks like:
                ,--------------------- backoff++ --------------.
               V                                               |
  START ---> Wait exp ------> Get oldest txn ID from ----> FAILURE
             backoff           DB and try to send it
                                 ^                |___________
Mark AS as                       |                            V
UP & quit           +---------- YES                       SUCCESS
    |               |                                         |
    NO <--- Have more txns? <------ Mark txn success & nuke <-+
                                      from db; incr AS pos.
                                         Reset backoff.

This is all tied together by the AppServiceScheduler which DIs the required
components.
"""
import logging
from typing import (
    TYPE_CHECKING,
    Awaitable,
    Callable,
    Collection,
    Dict,
    Iterable,
    List,
    Optional,
    Set,
    Tuple,
)

from synapse.appservice import (
    ApplicationService,
    ApplicationServiceState,
    TransactionOneTimeKeyCounts,
    TransactionUnusedFallbackKeys,
)
from synapse.appservice.api import ApplicationServiceApi
from synapse.events import EventBase
from synapse.logging.context import run_in_background
from synapse.metrics.background_process_metrics import run_as_background_process
from synapse.storage.databases.main import DataStore
from synapse.types import DeviceListUpdates, JsonDict
from synapse.util import Clock

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


# Maximum number of events to provide in an AS transaction.
MAX_PERSISTENT_EVENTS_PER_TRANSACTION = 100

# Maximum number of ephemeral events to provide in an AS transaction.
MAX_EPHEMERAL_EVENTS_PER_TRANSACTION = 100

# Maximum number of to-device messages to provide in an AS transaction.
MAX_TO_DEVICE_MESSAGES_PER_TRANSACTION = 100


class ApplicationServiceScheduler:
    """Public facing API for this module. Does the required DI to tie the
    components together. This also serves as the "event_pool", which in this
    case is a simple array.
    """

    def __init__(self, hs: "HomeServer"):
        self.clock = hs.get_clock()
        self.store = hs.get_datastores().main
        self.as_api = hs.get_application_service_api()

        self.txn_ctrl = _TransactionController(self.clock, self.store, self.as_api)
        self.queuer = _ServiceQueuer(self.txn_ctrl, self.clock, hs)

    async def start(self) -> None:
        logger.info("Starting appservice scheduler")

        # check for any DOWN ASes and start recoverers for them.
        services = await self.store.get_appservices_by_state(
            ApplicationServiceState.DOWN
        )

        for service in services:
            self.txn_ctrl.start_recoverer(service)

    def enqueue_for_appservice(
        self,
        appservice: ApplicationService,
        events: Optional[Collection[EventBase]] = None,
        ephemeral: Optional[Collection[JsonDict]] = None,
        to_device_messages: Optional[Collection[JsonDict]] = None,
        device_list_summary: Optional[DeviceListUpdates] = None,
    ) -> None:
        """
        Enqueue some data to be sent off to an application service.

        Args:
            appservice: The application service to create and send a transaction to.
            events: The persistent room events to send.
            ephemeral: The ephemeral events to send.
            to_device_messages: The to-device messages to send. These differ from normal
                to-device messages sent to clients, as they have 'to_device_id' and
                'to_user_id' fields.
            device_list_summary: A summary of users that the application service either needs
                to refresh the device lists of, or those that the application service need no
                longer track the device lists of.
        """
        # We purposefully allow this method to run with empty events/ephemeral
        # collections, so that callers do not need to check iterable size themselves.
        if (
            not events
            and not ephemeral
            and not to_device_messages
            and not device_list_summary
        ):
            return

        if events:
            self.queuer.queued_events.setdefault(appservice.id, []).extend(events)
        if ephemeral:
            self.queuer.queued_ephemeral.setdefault(appservice.id, []).extend(ephemeral)
        if to_device_messages:
            self.queuer.queued_to_device_messages.setdefault(appservice.id, []).extend(
                to_device_messages
            )
        if device_list_summary:
            self.queuer.queued_device_list_summaries.setdefault(
                appservice.id, []
            ).append(device_list_summary)

        # Kick off a new application service transaction
        self.queuer.start_background_request(appservice)


class _ServiceQueuer:
    """Queue of events waiting to be sent to appservices.

    Groups events into transactions per-appservice, and sends them on to the
    TransactionController. Makes sure that we only have one transaction in flight per
    appservice at a given time.
    """

    def __init__(
        self, txn_ctrl: "_TransactionController", clock: Clock, hs: "HomeServer"
    ):
        # dict of {service_id: [events]}
        self.queued_events: Dict[str, List[EventBase]] = {}
        # dict of {service_id: [events]}
        self.queued_ephemeral: Dict[str, List[JsonDict]] = {}
        # dict of {service_id: [to_device_message_json]}
        self.queued_to_device_messages: Dict[str, List[JsonDict]] = {}
        # dict of {service_id: [device_list_summary]}
        self.queued_device_list_summaries: Dict[str, List[DeviceListUpdates]] = {}

        # the appservices which currently have a transaction in flight
        self.requests_in_flight: Set[str] = set()
        self.txn_ctrl = txn_ctrl
        self.clock = clock
        self._msc3202_transaction_extensions_enabled: bool = (
            hs.config.experimental.msc3202_transaction_extensions
        )
        self._store = hs.get_datastores().main

    def start_background_request(self, service: ApplicationService) -> None:
        # start a sender for this appservice if we don't already have one
        if service.id in self.requests_in_flight:
            return

        run_as_background_process(
            "as-sender-%s" % (service.id,), self._send_request, service
        )

    async def _send_request(self, service: ApplicationService) -> None:
        # sanity-check: we shouldn't get here if this service already has a sender
        # running.
        assert service.id not in self.requests_in_flight

        self.requests_in_flight.add(service.id)
        try:
            while True:
                all_events = self.queued_events.get(service.id, [])
                events = all_events[:MAX_PERSISTENT_EVENTS_PER_TRANSACTION]
                del all_events[:MAX_PERSISTENT_EVENTS_PER_TRANSACTION]

                all_events_ephemeral = self.queued_ephemeral.get(service.id, [])
                ephemeral = all_events_ephemeral[:MAX_EPHEMERAL_EVENTS_PER_TRANSACTION]
                del all_events_ephemeral[:MAX_EPHEMERAL_EVENTS_PER_TRANSACTION]

                all_to_device_messages = self.queued_to_device_messages.get(
                    service.id, []
                )
                to_device_messages_to_send = all_to_device_messages[
                    :MAX_TO_DEVICE_MESSAGES_PER_TRANSACTION
                ]
                del all_to_device_messages[:MAX_TO_DEVICE_MESSAGES_PER_TRANSACTION]

                # Consolidate any pending device list summaries into a single, up-to-date
                # summary.
                # Note: this code assumes that in a single DeviceListUpdates, a user will
                # never be in both "changed" and "left" sets.
                device_list_summary = DeviceListUpdates()
                for summary in self.queued_device_list_summaries.get(service.id, []):
                    # For every user in the incoming "changed" set:
                    #   * Remove them from the existing "left" set if necessary
                    #     (as we need to start tracking them again)
                    #   * Add them to the existing "changed" set if necessary.
                    device_list_summary.left.difference_update(summary.changed)
                    device_list_summary.changed.update(summary.changed)

                    # For every user in the incoming "left" set:
                    #   * Remove them from the existing "changed" set if necessary
                    #     (we no longer need to track them)
                    #   * Add them to the existing "left" set if necessary.
                    device_list_summary.changed.difference_update(summary.left)
                    device_list_summary.left.update(summary.left)
                self.queued_device_list_summaries.clear()

                if (
                    not events
                    and not ephemeral
                    and not to_device_messages_to_send
                    # DeviceListUpdates is True if either the 'changed' or 'left' sets have
                    # at least one entry, otherwise False
                    and not device_list_summary
                ):
                    return

                one_time_key_counts: Optional[TransactionOneTimeKeyCounts] = None
                unused_fallback_keys: Optional[TransactionUnusedFallbackKeys] = None

                if (
                    self._msc3202_transaction_extensions_enabled
                    and service.msc3202_transaction_extensions
                ):
                    # Compute the one-time key counts and fallback key usage states
                    # for the users which are mentioned in this transaction,
                    # as well as the appservice's sender.
                    (
                        one_time_key_counts,
                        unused_fallback_keys,
                    ) = await self._compute_msc3202_otk_counts_and_fallback_keys(
                        service, events, ephemeral, to_device_messages_to_send
                    )

                try:
                    await self.txn_ctrl.send(
                        service,
                        events,
                        ephemeral,
                        to_device_messages_to_send,
                        one_time_key_counts,
                        unused_fallback_keys,
                        device_list_summary,
                    )
                except Exception:
                    logger.exception("AS request failed")
        finally:
            self.requests_in_flight.discard(service.id)

    async def _compute_msc3202_otk_counts_and_fallback_keys(
        self,
        service: ApplicationService,
        events: Iterable[EventBase],
        ephemerals: Iterable[JsonDict],
        to_device_messages: Iterable[JsonDict],
    ) -> Tuple[TransactionOneTimeKeyCounts, TransactionUnusedFallbackKeys]:
        """
        Given a list of the events, ephemeral messages and to-device messages,
        - first computes a list of application services users that may have
          interesting updates to the one-time key counts or fallback key usage.
        - then computes one-time key counts and fallback key usages for those users.
        Given a list of application service users that are interesting,
        compute one-time key counts and fallback key usages for the users.
        """

        # Set of 'interesting' users who may have updates
        users: Set[str] = set()

        # The sender is always included
        users.add(service.sender)

        # All AS users that would receive the PDUs or EDUs sent to these rooms
        # are classed as 'interesting'.
        rooms_of_interesting_users: Set[str] = set()
        # PDUs
        rooms_of_interesting_users.update(event.room_id for event in events)
        # EDUs
        rooms_of_interesting_users.update(
            ephemeral["room_id"]
            for ephemeral in ephemerals
            if ephemeral.get("room_id") is not None
        )

        # Look up the AS users in those rooms
        for room_id in rooms_of_interesting_users:
            users.update(
                await self._store.get_app_service_users_in_room(room_id, service)
            )

        # Add recipients of to-device messages.
        users.update(
            device_message["to_user_id"] for device_message in to_device_messages
        )

        # Compute and return the counts / fallback key usage states
        otk_counts = await self._store.count_bulk_e2e_one_time_keys_for_as(users)
        unused_fbks = await self._store.get_e2e_bulk_unused_fallback_key_types(users)
        return otk_counts, unused_fbks


class _TransactionController:
    """Transaction manager.

    Builds AppServiceTransactions and runs their lifecycle. Also starts a Recoverer
    if a transaction fails.

    (Note we have only have one of these in the homeserver.)
    """

    def __init__(self, clock: Clock, store: DataStore, as_api: ApplicationServiceApi):
        self.clock = clock
        self.store = store
        self.as_api = as_api

        # map from service id to recoverer instance
        self.recoverers: Dict[str, "_Recoverer"] = {}

        # for UTs
        self.RECOVERER_CLASS = _Recoverer

    async def send(
        self,
        service: ApplicationService,
        events: List[EventBase],
        ephemeral: Optional[List[JsonDict]] = None,
        to_device_messages: Optional[List[JsonDict]] = None,
        one_time_key_counts: Optional[TransactionOneTimeKeyCounts] = None,
        unused_fallback_keys: Optional[TransactionUnusedFallbackKeys] = None,
        device_list_summary: Optional[DeviceListUpdates] = None,
    ) -> None:
        """
        Create a transaction with the given data and send to the provided
        application service.

        Args:
            service: The application service to send the transaction to.
            events: The persistent events to include in the transaction.
            ephemeral: The ephemeral events to include in the transaction.
            to_device_messages: The to-device messages to include in the transaction.
            one_time_key_counts: Counts of remaining one-time keys for relevant
                appservice devices in the transaction.
            unused_fallback_keys: Lists of unused fallback keys for relevant
                appservice devices in the transaction.
            device_list_summary: The device list summary to include in the transaction.
        """
        try:
            service_is_up = await self._is_service_up(service)
            # Don't create empty txns when in recovery mode (ephemeral events are dropped)
            if not service_is_up and not events:
                return

            txn = await self.store.create_appservice_txn(
                service=service,
                events=events,
                ephemeral=ephemeral or [],
                to_device_messages=to_device_messages or [],
                one_time_key_counts=one_time_key_counts or {},
                unused_fallback_keys=unused_fallback_keys or {},
                device_list_summary=device_list_summary or DeviceListUpdates(),
            )
            if service_is_up:
                sent = await txn.send(self.as_api)
                if sent:
                    await txn.complete(self.store)
                else:
                    run_in_background(self._on_txn_fail, service)
        except Exception:
            logger.exception("Error creating appservice transaction")
            run_in_background(self._on_txn_fail, service)

    async def on_recovered(self, recoverer: "_Recoverer") -> None:
        logger.info(
            "Successfully recovered application service AS ID %s", recoverer.service.id
        )
        self.recoverers.pop(recoverer.service.id)
        logger.info("Remaining active recoverers: %s", len(self.recoverers))
        await self.store.set_appservice_state(
            recoverer.service, ApplicationServiceState.UP
        )

    async def _on_txn_fail(self, service: ApplicationService) -> None:
        try:
            await self.store.set_appservice_state(service, ApplicationServiceState.DOWN)
            self.start_recoverer(service)
        except Exception:
            logger.exception("Error starting AS recoverer")

    def start_recoverer(self, service: ApplicationService) -> None:
        """Start a Recoverer for the given service

        Args:
            service:
        """
        logger.info("Starting recoverer for AS ID %s", service.id)
        assert service.id not in self.recoverers
        recoverer = self.RECOVERER_CLASS(
            self.clock, self.store, self.as_api, service, self.on_recovered
        )
        self.recoverers[service.id] = recoverer
        recoverer.recover()
        logger.info("Now %i active recoverers", len(self.recoverers))

    async def _is_service_up(self, service: ApplicationService) -> bool:
        state = await self.store.get_appservice_state(service)
        return state == ApplicationServiceState.UP or state is None


class _Recoverer:
    """Manages retries and backoff for a DOWN appservice.

    We have one of these for each appservice which is currently considered DOWN.

    Args:
        clock (synapse.util.Clock):
        store (synapse.storage.DataStore):
        as_api (synapse.appservice.api.ApplicationServiceApi):
        service (synapse.appservice.ApplicationService): the service we are managing
        callback (callable[_Recoverer]): called once the service recovers.
    """

    def __init__(
        self,
        clock: Clock,
        store: DataStore,
        as_api: ApplicationServiceApi,
        service: ApplicationService,
        callback: Callable[["_Recoverer"], Awaitable[None]],
    ):
        self.clock = clock
        self.store = store
        self.as_api = as_api
        self.service = service
        self.callback = callback
        self.backoff_counter = 1

    def recover(self) -> None:
        def _retry() -> None:
            run_as_background_process(
                "as-recoverer-%s" % (self.service.id,), self.retry
            )

        delay = 2**self.backoff_counter
        logger.info("Scheduling retries on %s in %fs", self.service.id, delay)
        self.clock.call_later(delay, _retry)

    def _backoff(self) -> None:
        # cap the backoff to be around 8.5min => (2^9) = 512 secs
        if self.backoff_counter < 9:
            self.backoff_counter += 1
        self.recover()

    async def retry(self) -> None:
        logger.info("Starting retries on %s", self.service.id)
        try:
            while True:
                txn = await self.store.get_oldest_unsent_txn(self.service)
                if not txn:
                    # nothing left: we're done!
                    await self.callback(self)
                    return

                logger.info(
                    "Retrying transaction %s for AS ID %s", txn.id, txn.service.id
                )
                sent = await txn.send(self.as_api)
                if not sent:
                    break

                await txn.complete(self.store)

                # reset the backoff counter and then process the next transaction
                self.backoff_counter = 1

        except Exception:
            logger.exception("Unexpected error running retries")

        # we didn't manage to send all of the transactions before we got an error of
        # some flavour: reschedule the next retry.
        self._backoff()
