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
from twisted.internet import defer

from synapse.appservice import ApplicationServiceState
from synapse.util.logcontext import preserve_fn
from synapse.util.metrics import Measure

import logging

logger = logging.getLogger(__name__)


class ApplicationServiceScheduler(object):
    """ Public facing API for this module. Does the required DI to tie the
    components together. This also serves as the "event_pool", which in this
    case is a simple array.
    """

    def __init__(self, hs):
        self.clock = hs.get_clock()
        self.store = hs.get_datastore()
        self.as_api = hs.get_application_service_api()

        def create_recoverer(service, callback):
            return _Recoverer(self.clock, self.store, self.as_api, service, callback)

        self.txn_ctrl = _TransactionController(
            self.clock, self.store, self.as_api, create_recoverer
        )
        self.queuer = _ServiceQueuer(self.txn_ctrl, self.clock)

    @defer.inlineCallbacks
    def start(self):
        logger.info("Starting appservice scheduler")
        # check for any DOWN ASes and start recoverers for them.
        recoverers = yield _Recoverer.start(
            self.clock, self.store, self.as_api, self.txn_ctrl.on_recovered
        )
        self.txn_ctrl.add_recoverers(recoverers)

    def submit_event_for_as(self, service, event):
        self.queuer.enqueue(service, event)


class _ServiceQueuer(object):
    """Queues events for the same application service together, sending
    transactions as soon as possible. Once a transaction is sent successfully,
    this schedules any other events in the queue to run.
    """

    def __init__(self, txn_ctrl, clock):
        self.queued_events = {}  # dict of {service_id: [events]}
        self.requests_in_flight = set()
        self.txn_ctrl = txn_ctrl
        self.clock = clock

    def enqueue(self, service, event):
        # if this service isn't being sent something
        self.queued_events.setdefault(service.id, []).append(event)
        preserve_fn(self._send_request)(service)

    @defer.inlineCallbacks
    def _send_request(self, service):
        if service.id in self.requests_in_flight:
            return

        self.requests_in_flight.add(service.id)
        try:
            while True:
                events = self.queued_events.pop(service.id, [])
                if not events:
                    return

                with Measure(self.clock, "servicequeuer.send"):
                    try:
                        yield self.txn_ctrl.send(service, events)
                    except:
                        logger.exception("AS request failed")
        finally:
            self.requests_in_flight.discard(service.id)


class _TransactionController(object):

    def __init__(self, clock, store, as_api, recoverer_fn):
        self.clock = clock
        self.store = store
        self.as_api = as_api
        self.recoverer_fn = recoverer_fn
        # keep track of how many recoverers there are
        self.recoverers = []

    @defer.inlineCallbacks
    def send(self, service, events):
        try:
            txn = yield self.store.create_appservice_txn(
                service=service,
                events=events
            )
            service_is_up = yield self._is_service_up(service)
            if service_is_up:
                sent = yield txn.send(self.as_api)
                if sent:
                    yield txn.complete(self.store)
                else:
                    preserve_fn(self._start_recoverer)(service)
        except Exception as e:
            logger.exception(e)
            preserve_fn(self._start_recoverer)(service)

    @defer.inlineCallbacks
    def on_recovered(self, recoverer):
        self.recoverers.remove(recoverer)
        logger.info("Successfully recovered application service AS ID %s",
                    recoverer.service.id)
        logger.info("Remaining active recoverers: %s", len(self.recoverers))
        yield self.store.set_appservice_state(
            recoverer.service,
            ApplicationServiceState.UP
        )

    def add_recoverers(self, recoverers):
        for r in recoverers:
            self.recoverers.append(r)
        if len(recoverers) > 0:
            logger.info("New active recoverers: %s", len(self.recoverers))

    @defer.inlineCallbacks
    def _start_recoverer(self, service):
        yield self.store.set_appservice_state(
            service,
            ApplicationServiceState.DOWN
        )
        logger.info(
            "Application service falling behind. Starting recoverer. AS ID %s",
            service.id
        )
        recoverer = self.recoverer_fn(service, self.on_recovered)
        self.add_recoverers([recoverer])
        recoverer.recover()

    @defer.inlineCallbacks
    def _is_service_up(self, service):
        state = yield self.store.get_appservice_state(service)
        defer.returnValue(state == ApplicationServiceState.UP or state is None)


class _Recoverer(object):

    @staticmethod
    @defer.inlineCallbacks
    def start(clock, store, as_api, callback):
        services = yield store.get_appservices_by_state(
            ApplicationServiceState.DOWN
        )
        recoverers = [
            _Recoverer(clock, store, as_api, s, callback) for s in services
        ]
        for r in recoverers:
            logger.info("Starting recoverer for AS ID %s which was marked as "
                        "DOWN", r.service.id)
            r.recover()
        defer.returnValue(recoverers)

    def __init__(self, clock, store, as_api, service, callback):
        self.clock = clock
        self.store = store
        self.as_api = as_api
        self.service = service
        self.callback = callback
        self.backoff_counter = 1

    def recover(self):
        self.clock.call_later((2 ** self.backoff_counter), self.retry)

    def _backoff(self):
        # cap the backoff to be around 8.5min => (2^9) = 512 secs
        if self.backoff_counter < 9:
            self.backoff_counter += 1
        self.recover()

    @defer.inlineCallbacks
    def retry(self):
        try:
            txn = yield self.store.get_oldest_unsent_txn(self.service)
            if txn:
                logger.info("Retrying transaction %s for AS ID %s",
                            txn.id, txn.service.id)
                sent = yield txn.send(self.as_api)
                if sent:
                    yield txn.complete(self.store)
                    # reset the backoff counter and retry immediately
                    self.backoff_counter = 1
                    yield self.retry()
                else:
                    self._backoff()
            else:
                self._set_service_recovered()
        except Exception as e:
            logger.exception(e)
            self._backoff()

    def _set_service_recovered(self):
        self.callback(self)
