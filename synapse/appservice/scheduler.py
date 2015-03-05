# -*- coding: utf-8 -*-
# Copyright 2015 OpenMarket Ltd
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
                    ___________
  \O/ --- event -->|           |                           +--------------+
   |  - event ---->| event_pool|<-- poll 1/s for events ---|  EventSorter |
  / \ ---- event ->|___________|                           +--------------+
 USERS                                 ____________________________|
                                      |        |       |
                                      V        V       V
                                     ASa       ASb     ASc
                                    [e,e]      [e]   [e,e,e]
                                      |
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
                                 ^                |__________
Mark AS as                       |                           V
UP & quit           +---------- YES                      SUCCESS
    |               |                                        |
    NO <--- Have more txns? <------ Mark txn success & nuke -+
                                      from db; incr AS pos.

This is all tied together by the AppServiceScheduler which DIs the required
components.
"""


class AppServiceScheduler(object):
    """ Public facing API for this module. Does the required DI to tie the
    components together. This also serves as the "event_pool", which in this
    case is a simple array.
    """

    def __init__(self, store, as_api, services):
        self.app_services = services
        self.event_pool = []

        def create_recoverer(service):
            return _Recoverer(store, as_api, service)
        self.txn_ctrl = _TransactionController(store, as_api, create_recoverer)

        self.event_sorter = _EventSorter(self, self.txn_ctrl, services)

    def start(self):
        self.event_sorter.start_polling()

    def store_event(self, event):  # event_pool
        self.event_pool.append(event)

    def get_events(self):  # event_pool
        return self.event_pool


class AppServiceTransaction(object):
    """Represents an application service transaction."""

    def __init__(self, service, id, events):
        self.service = service
        self.id = id
        self.events = events

    def send(self, as_api):
        # sends this transaction using this as_api
        pass

    def complete(self, store):
        # increment txn id on AS and nuke txn contents from db
        pass


class _EventSorter(object):

    def __init__(self, event_pool, txn_ctrl, services):
        self.event_pool = event_pool
        self.txn_ctrl = txn_ctrl
        self.services = services

    def start_polling(self):
        events = self.event_pool.get_events()
        if events:
            self._process(events)
        # repoll later on

    def _process(self, events):
        # sort events
        # f.e. (AS, events) => poke transaction controller
        pass


class _TransactionController(object):

    def __init__(self, store, as_api, recoverer_fn):
        self.store = store
        self.as_api = as_api
        self.recoverer_fn = recoverer_fn

    def on_receive_events(self, service, events):
        txn = self._store_txn(service, events)
        if txn.send(self.as_api):
            txn.complete(self.store)
        else:
            self._start_recoverer(service)

    def _start_recoverer(self, service):
        recoverer = self.recoverer_fn(service)
        recoverer.recover()

    def _store_txn(self, service, events):
        pass  # returns AppServiceTransaction


class _Recoverer(object):

    def __init__(self, store, as_api, service):
        self.store = store
        self.as_api = as_api
        self.service = service
        self.backoff_counter = 1

    def recover(self):
        # TODO wait a bit
        txn = self._get_oldest_txn()
        if txn:
            if txn.send(self.as_api):
                txn.complete(self.store)
            else:
                self.backoff_counter += 1
                self.recover(self.service)
                return
        else:
            self._set_service_recovered(self.service)

    def _set_service_recovered(self, service):
        pass

    def _get_oldest_txn(self):
        pass  # returns AppServiceTransaction


