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
from unittest.mock import Mock

from twisted.internet import defer

from synapse.appservice import ApplicationServiceState
from synapse.appservice.scheduler import (
    _Recoverer,
    _ServiceQueuer,
    _TransactionController,
)
from synapse.logging.context import make_deferred_yieldable

from tests import unittest
from tests.test_utils import make_awaitable

from ..utils import MockClock


class ApplicationServiceSchedulerTransactionCtrlTestCase(unittest.TestCase):
    def setUp(self):
        self.clock = MockClock()
        self.store = Mock()
        self.as_api = Mock()
        self.recoverer = Mock()
        self.recoverer_fn = Mock(return_value=self.recoverer)
        self.txnctrl = _TransactionController(
            clock=self.clock, store=self.store, as_api=self.as_api
        )
        self.txnctrl.RECOVERER_CLASS = self.recoverer_fn

    def test_single_service_up_txn_sent(self):
        # Test: The AS is up and the txn is successfully sent.
        service = Mock()
        events = [Mock(), Mock()]
        txn_id = "foobar"
        txn = Mock(id=txn_id, service=service, events=events)

        # mock methods
        self.store.get_appservice_state = Mock(
            return_value=defer.succeed(ApplicationServiceState.UP)
        )
        txn.send = Mock(return_value=make_awaitable(True))
        self.store.create_appservice_txn = Mock(return_value=defer.succeed(txn))

        # actual call
        self.successResultOf(defer.ensureDeferred(self.txnctrl.send(service, events)))

        self.store.create_appservice_txn.assert_called_once_with(
            service=service, events=events, ephemeral=[]  # txn made and saved
        )
        self.assertEquals(0, len(self.txnctrl.recoverers))  # no recoverer made
        txn.complete.assert_called_once_with(self.store)  # txn completed

    def test_single_service_down(self):
        # Test: The AS is down so it shouldn't push; Recoverers will do it.
        # It should still make a transaction though.
        service = Mock()
        events = [Mock(), Mock()]

        txn = Mock(id="idhere", service=service, events=events)
        self.store.get_appservice_state = Mock(
            return_value=defer.succeed(ApplicationServiceState.DOWN)
        )
        self.store.create_appservice_txn = Mock(return_value=defer.succeed(txn))

        # actual call
        self.successResultOf(defer.ensureDeferred(self.txnctrl.send(service, events)))

        self.store.create_appservice_txn.assert_called_once_with(
            service=service, events=events, ephemeral=[]  # txn made and saved
        )
        self.assertEquals(0, txn.send.call_count)  # txn not sent though
        self.assertEquals(0, txn.complete.call_count)  # or completed

    def test_single_service_up_txn_not_sent(self):
        # Test: The AS is up and the txn is not sent. A Recoverer is made and
        # started.
        service = Mock()
        events = [Mock(), Mock()]
        txn_id = "foobar"
        txn = Mock(id=txn_id, service=service, events=events)

        # mock methods
        self.store.get_appservice_state = Mock(
            return_value=defer.succeed(ApplicationServiceState.UP)
        )
        self.store.set_appservice_state = Mock(return_value=defer.succeed(True))
        txn.send = Mock(return_value=make_awaitable(False))  # fails to send
        self.store.create_appservice_txn = Mock(return_value=defer.succeed(txn))

        # actual call
        self.successResultOf(defer.ensureDeferred(self.txnctrl.send(service, events)))

        self.store.create_appservice_txn.assert_called_once_with(
            service=service, events=events, ephemeral=[]
        )
        self.assertEquals(1, self.recoverer_fn.call_count)  # recoverer made
        self.assertEquals(1, self.recoverer.recover.call_count)  # and invoked
        self.assertEquals(1, len(self.txnctrl.recoverers))  # and stored
        self.assertEquals(0, txn.complete.call_count)  # txn not completed
        self.store.set_appservice_state.assert_called_once_with(
            service, ApplicationServiceState.DOWN  # service marked as down
        )


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

    def test_recover_single_txn(self):
        txn = Mock()
        # return one txn to send, then no more old txns
        txns = [txn, None]

        def take_txn(*args, **kwargs):
            return defer.succeed(txns.pop(0))

        self.store.get_oldest_unsent_txn = Mock(side_effect=take_txn)

        self.recoverer.recover()
        # shouldn't have called anything prior to waiting for exp backoff
        self.assertEquals(0, self.store.get_oldest_unsent_txn.call_count)
        txn.send = Mock(return_value=make_awaitable(True))
        txn.complete.return_value = make_awaitable(None)
        # wait for exp backoff
        self.clock.advance_time(2)
        self.assertEquals(1, txn.send.call_count)
        self.assertEquals(1, txn.complete.call_count)
        # 2 because it needs to get None to know there are no more txns
        self.assertEquals(2, self.store.get_oldest_unsent_txn.call_count)
        self.callback.assert_called_once_with(self.recoverer)
        self.assertEquals(self.recoverer.service, self.service)

    def test_recover_retry_txn(self):
        txn = Mock()
        txns = [txn, None]
        pop_txn = False

        def take_txn(*args, **kwargs):
            if pop_txn:
                return defer.succeed(txns.pop(0))
            else:
                return defer.succeed(txn)

        self.store.get_oldest_unsent_txn = Mock(side_effect=take_txn)

        self.recoverer.recover()
        self.assertEquals(0, self.store.get_oldest_unsent_txn.call_count)
        txn.send = Mock(return_value=make_awaitable(False))
        txn.complete.return_value = make_awaitable(None)
        self.clock.advance_time(2)
        self.assertEquals(1, txn.send.call_count)
        self.assertEquals(0, txn.complete.call_count)
        self.assertEquals(0, self.callback.call_count)
        self.clock.advance_time(4)
        self.assertEquals(2, txn.send.call_count)
        self.assertEquals(0, txn.complete.call_count)
        self.assertEquals(0, self.callback.call_count)
        self.clock.advance_time(8)
        self.assertEquals(3, txn.send.call_count)
        self.assertEquals(0, txn.complete.call_count)
        self.assertEquals(0, self.callback.call_count)
        txn.send = Mock(return_value=make_awaitable(True))  # successfully send the txn
        pop_txn = True  # returns the txn the first time, then no more.
        self.clock.advance_time(16)
        self.assertEquals(1, txn.send.call_count)  # new mock reset call count
        self.assertEquals(1, txn.complete.call_count)
        self.callback.assert_called_once_with(self.recoverer)


class ApplicationServiceSchedulerQueuerTestCase(unittest.TestCase):
    def setUp(self):
        self.txn_ctrl = Mock()
        self.queuer = _ServiceQueuer(self.txn_ctrl, MockClock())

    def test_send_single_event_no_queue(self):
        # Expect the event to be sent immediately.
        service = Mock(id=4)
        event = Mock()
        self.queuer.enqueue_event(service, event)
        self.txn_ctrl.send.assert_called_once_with(service, [event], [])

    def test_send_single_event_with_queue(self):
        d = defer.Deferred()
        self.txn_ctrl.send = Mock(
            side_effect=lambda x, y, z: make_deferred_yieldable(d)
        )
        service = Mock(id=4)
        event = Mock(event_id="first")
        event2 = Mock(event_id="second")
        event3 = Mock(event_id="third")
        # Send an event and don't resolve it just yet.
        self.queuer.enqueue_event(service, event)
        # Send more events: expect send() to NOT be called multiple times.
        self.queuer.enqueue_event(service, event2)
        self.queuer.enqueue_event(service, event3)
        self.txn_ctrl.send.assert_called_with(service, [event], [])
        self.assertEquals(1, self.txn_ctrl.send.call_count)
        # Resolve the send event: expect the queued events to be sent
        d.callback(service)
        self.txn_ctrl.send.assert_called_with(service, [event2, event3], [])
        self.assertEquals(2, self.txn_ctrl.send.call_count)

    def test_multiple_service_queues(self):
        # Tests that each service has its own queue, and that they don't block
        # on each other.
        srv1 = Mock(id=4)
        srv_1_defer = defer.Deferred()
        srv_1_event = Mock(event_id="srv1a")
        srv_1_event2 = Mock(event_id="srv1b")

        srv2 = Mock(id=6)
        srv_2_defer = defer.Deferred()
        srv_2_event = Mock(event_id="srv2a")
        srv_2_event2 = Mock(event_id="srv2b")

        send_return_list = [srv_1_defer, srv_2_defer]

        def do_send(x, y, z):
            return make_deferred_yieldable(send_return_list.pop(0))

        self.txn_ctrl.send = Mock(side_effect=do_send)

        # send events for different ASes and make sure they are sent
        self.queuer.enqueue_event(srv1, srv_1_event)
        self.queuer.enqueue_event(srv1, srv_1_event2)
        self.txn_ctrl.send.assert_called_with(srv1, [srv_1_event], [])
        self.queuer.enqueue_event(srv2, srv_2_event)
        self.queuer.enqueue_event(srv2, srv_2_event2)
        self.txn_ctrl.send.assert_called_with(srv2, [srv_2_event], [])

        # make sure callbacks for a service only send queued events for THAT
        # service
        srv_2_defer.callback(srv2)
        self.txn_ctrl.send.assert_called_with(srv2, [srv_2_event2], [])
        self.assertEquals(3, self.txn_ctrl.send.call_count)

    def test_send_large_txns(self):
        srv_1_defer = defer.Deferred()
        srv_2_defer = defer.Deferred()
        send_return_list = [srv_1_defer, srv_2_defer]

        def do_send(x, y, z):
            return make_deferred_yieldable(send_return_list.pop(0))

        self.txn_ctrl.send = Mock(side_effect=do_send)

        service = Mock(id=4, name="service")
        event_list = [Mock(name="event%i" % (i + 1)) for i in range(200)]
        for event in event_list:
            self.queuer.enqueue_event(service, event)

        # Expect the first event to be sent immediately.
        self.txn_ctrl.send.assert_called_with(service, [event_list[0]], [])
        srv_1_defer.callback(service)
        # Then send the next 100 events
        self.txn_ctrl.send.assert_called_with(service, event_list[1:101], [])
        srv_2_defer.callback(service)
        # Then the final 99 events
        self.txn_ctrl.send.assert_called_with(service, event_list[101:], [])
        self.assertEquals(3, self.txn_ctrl.send.call_count)

    def test_send_single_ephemeral_no_queue(self):
        # Expect the event to be sent immediately.
        service = Mock(id=4, name="service")
        event_list = [Mock(name="event")]
        self.queuer.enqueue_ephemeral(service, event_list)
        self.txn_ctrl.send.assert_called_once_with(service, [], event_list)

    def test_send_multiple_ephemeral_no_queue(self):
        # Expect the event to be sent immediately.
        service = Mock(id=4, name="service")
        event_list = [Mock(name="event1"), Mock(name="event2"), Mock(name="event3")]
        self.queuer.enqueue_ephemeral(service, event_list)
        self.txn_ctrl.send.assert_called_once_with(service, [], event_list)

    def test_send_single_ephemeral_with_queue(self):
        d = defer.Deferred()
        self.txn_ctrl.send = Mock(
            side_effect=lambda x, y, z: make_deferred_yieldable(d)
        )
        service = Mock(id=4)
        event_list_1 = [Mock(event_id="event1"), Mock(event_id="event2")]
        event_list_2 = [Mock(event_id="event3"), Mock(event_id="event4")]
        event_list_3 = [Mock(event_id="event5"), Mock(event_id="event6")]

        # Send an event and don't resolve it just yet.
        self.queuer.enqueue_ephemeral(service, event_list_1)
        # Send more events: expect send() to NOT be called multiple times.
        self.queuer.enqueue_ephemeral(service, event_list_2)
        self.queuer.enqueue_ephemeral(service, event_list_3)
        self.txn_ctrl.send.assert_called_with(service, [], event_list_1)
        self.assertEquals(1, self.txn_ctrl.send.call_count)
        # Resolve txn_ctrl.send
        d.callback(service)
        # Expect the queued events to be sent
        self.txn_ctrl.send.assert_called_with(service, [], event_list_2 + event_list_3)
        self.assertEquals(2, self.txn_ctrl.send.call_count)

    def test_send_large_txns_ephemeral(self):
        d = defer.Deferred()
        self.txn_ctrl.send = Mock(
            side_effect=lambda x, y, z: make_deferred_yieldable(d)
        )
        # Expect the event to be sent immediately.
        service = Mock(id=4, name="service")
        first_chunk = [Mock(name="event%i" % (i + 1)) for i in range(100)]
        second_chunk = [Mock(name="event%i" % (i + 101)) for i in range(50)]
        event_list = first_chunk + second_chunk
        self.queuer.enqueue_ephemeral(service, event_list)
        self.txn_ctrl.send.assert_called_once_with(service, [], first_chunk)
        d.callback(service)
        self.txn_ctrl.send.assert_called_with(service, [], second_chunk)
        self.assertEquals(2, self.txn_ctrl.send.call_count)
