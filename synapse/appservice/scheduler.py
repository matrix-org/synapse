# -*- coding: utf-8 -*-
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

from synapse.appservice import ApplicationServiceState
from synapse.logging.context import run_in_background
from synapse.metrics.background_process_metrics import run_as_background_process

logger = logging.getLogger(__name__)


class ApplicationServiceScheduler:
    """ Public facing API for this module. Does the required DI to tie the
    components together. This also serves as the "event_pool", which in this
    case is a simple array.
    """

    def __init__(self, hs):
        self.clock = hs.get_clock()
        self.store = hs.get_datastore()
        self.as_api = hs.get_application_service_api()

        self.txn_ctrl = _TransactionController(self.clock, self.store, self.as_api)
        self.queuer = _ServiceQueuer(self.txn_ctrl, self.clock)

    async def start(self):
        logger.info("Starting appservice scheduler")

        # check for any DOWN ASes and start recoverers for them.
        services = await self.store.get_appservices_by_state(
            ApplicationServiceState.DOWN
        )

        for service in services:
            self.txn_ctrl.start_recoverer(service)

    def submit_event_for_as(self, service, event):
        self.queuer.enqueue(service, event)


class _ServiceQueuer:
    """Queue of events waiting to be sent to appservices.

    Groups events into transactions per-appservice, and sends them on to the
    TransactionController. Makes sure that we only have one transaction in flight per
    appservice at a given time.
    """

    def __init__(self, txn_ctrl, clock):
        self.queued_events = {}  # dict of {service_id: [events]}

        # the appservices which currently have a transaction in flight
        self.requests_in_flight = set()
        self.txn_ctrl = txn_ctrl
        self.clock = clock

    def enqueue(self, service, event):
        self.queued_events.setdefault(service.id, []).append(event)

        # start a sender for this appservice if we don't already have one

        if service.id in self.requests_in_flight:
            return

        run_as_background_process(
            "as-sender-%s" % (service.id,), self._send_request, service
        )

    async def _send_request(self, service):
        # sanity-check: we shouldn't get here if this service already has a sender
        # running.
        assert service.id not in self.requests_in_flight

        self.requests_in_flight.add(service.id)
        try:
            while True:
                events = self.queued_events.pop(service.id, [])
                if not events:
                    return
                try:
                    await self.txn_ctrl.send(service, events)
                except Exception:
                    logger.exception("AS request failed")
        finally:
            self.requests_in_flight.discard(service.id)


class _TransactionController:
    """Transaction manager.

    Builds AppServiceTransactions and runs their lifecycle. Also starts a Recoverer
    if a transaction fails.

    (Note we have only have one of these in the homeserver.)

    Args:
        clock (synapse.util.Clock):
        store (synapse.storage.DataStore):
        as_api (synapse.appservice.api.ApplicationServiceApi):
    """

    def __init__(self, clock, store, as_api):
        self.clock = clock
        self.store = store
        self.as_api = as_api

        # map from service id to recoverer instance
        self.recoverers = {}

        # for UTs
        self.RECOVERER_CLASS = _Recoverer

    async def send(self, service, events):
        try:
            txn = await self.store.create_appservice_txn(service=service, events=events)
            service_is_up = await self._is_service_up(service)
            if service_is_up:
                sent = await txn.send(self.as_api)
                if sent:
                    await txn.complete(self.store)
                else:
                    run_in_background(self._on_txn_fail, service)
        except Exception:
            logger.exception("Error creating appservice transaction")
            run_in_background(self._on_txn_fail, service)

    async def on_recovered(self, recoverer):
        logger.info(
            "Successfully recovered application service AS ID %s", recoverer.service.id
        )
        self.recoverers.pop(recoverer.service.id)
        logger.info("Remaining active recoverers: %s", len(self.recoverers))
        await self.store.set_appservice_state(
            recoverer.service, ApplicationServiceState.UP
        )

    async def _on_txn_fail(self, service):
        try:
            await self.store.set_appservice_state(service, ApplicationServiceState.DOWN)
            self.start_recoverer(service)
        except Exception:
            logger.exception("Error starting AS recoverer")

    def start_recoverer(self, service):
        """Start a Recoverer for the given service

        Args:
            service (synapse.appservice.ApplicationService):
        """
        logger.info("Starting recoverer for AS ID %s", service.id)
        assert service.id not in self.recoverers
        recoverer = self.RECOVERER_CLASS(
            self.clock, self.store, self.as_api, service, self.on_recovered
        )
        self.recoverers[service.id] = recoverer
        recoverer.recover()
        logger.info("Now %i active recoverers", len(self.recoverers))

    async def _is_service_up(self, service):
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

    def __init__(self, clock, store, as_api, service, callback):
        self.clock = clock
        self.store = store
        self.as_api = as_api
        self.service = service
        self.callback = callback
        self.backoff_counter = 1

    def recover(self):
        def _retry():
            run_as_background_process(
                "as-recoverer-%s" % (self.service.id,), self.retry
            )

        delay = 2 ** self.backoff_counter
        logger.info("Scheduling retries on %s in %fs", self.service.id, delay)
        self.clock.call_later(delay, _retry)

    def _backoff(self):
        # cap the backoff to be around 8.5min => (2^9) = 512 secs
        if self.backoff_counter < 9:
            self.backoff_counter += 1
        self.recover()

    async def retry(self):
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
