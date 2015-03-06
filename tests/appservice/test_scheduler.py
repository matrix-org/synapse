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
from synapse.appservice.scheduler import (
    AppServiceScheduler, AppServiceTransaction, _EventGrouper,
    _TransactionController, _Recoverer
)
from twisted.internet import defer
from ..utils import MockClock
from mock import Mock
from tests import unittest

class ApplicationServiceSchedulerRecovererTestCase(unittest.TestCase):

    def setUp(self):
        self.clock = MockClock()
        self.as_api = Mock()
        self.store = Mock()
        self.service = Mock()
        self.callback = Mock()
        self.recoverer = _Recoverer(
            clock=self.clock,
            as_api=self.as_api,
            store=self.store,
            service=self.service,
            callback=self.callback,
        )

    def test_recover_service_single_txn(self):
        txns = self._mk_txns(1)
        self.store.get_oldest_txn = Mock(return_value=defer.succeed(txns[0]))

        self.recoverer.recover()
        self.assertEquals(0, self.store.get_oldest_txn.call_count)
        self.clock.advance_time(2000)
        self.assertEquals(2, self.store.get_oldest_txn.call_count)

    def _mk_txns(self, num_txns):
        return [
            Mock() for i in range(num_txns)
        ]



class ApplicationServiceSchedulerEventGrouperTestCase(unittest.TestCase):

    def setUp(self):
        self.grouper = _EventGrouper()

    def test_drain_single_event(self):
        service = Mock()
        event = Mock()
        self.grouper.on_receive(service, event)
        groups = self.grouper.drain_groups()
        self.assertTrue(service in groups)
        self.assertEquals([event], groups[service])
        self.assertEquals(1, len(groups.keys()))
        # no more events
        self.assertEquals(self.grouper.drain_groups(), {})

    def test_drain_multiple_events(self):
        service = Mock()
        events = [Mock(), Mock(), Mock()]
        for e in events:
            self.grouper.on_receive(service, e)
        groups = self.grouper.drain_groups()
        self.assertTrue(service in groups)
        self.assertEquals(events, groups[service])
        # no more events
        self.assertEquals(self.grouper.drain_groups(), {})

    def test_drain_multiple_services(self):
        services = [Mock(), Mock(), Mock()]
        events_a = [Mock(), Mock()]
        events_b = [Mock()]
        events_c = [Mock(), Mock(), Mock(), Mock()]
        mappings = {
            services[0]: events_a,
            services[1]: events_b,
            services[2]: events_c
        }
        for e in events_b:
            self.grouper.on_receive(services[1], e)
        for e in events_c:
            self.grouper.on_receive(services[2], e)
        for e in events_a:
            self.grouper.on_receive(services[0], e)

        groups = self.grouper.drain_groups()
        for service in services:
            self.assertTrue(service in groups)
            self.assertEquals(mappings[service], groups[service])
        self.assertEquals(3, len(groups.keys()))
        # no more events
        self.assertEquals(self.grouper.drain_groups(), {})
