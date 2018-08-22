# Copyright 2016 OpenMarket Ltd
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
import tempfile

from mock import Mock, NonCallableMock

from twisted.internet import defer, reactor
from twisted.internet.defer import Deferred

from synapse.replication.tcp.client import (
    ReplicationClientFactory,
    ReplicationClientHandler,
)
from synapse.replication.tcp.resource import ReplicationStreamProtocolFactory
from synapse.util.logcontext import PreserveLoggingContext, make_deferred_yieldable

from tests import unittest
from tests.utils import setup_test_homeserver


class TestReplicationClientHandler(ReplicationClientHandler):
    """Overrides on_rdata so that we can wait for it to happen"""

    def __init__(self, store):
        super(TestReplicationClientHandler, self).__init__(store)
        self._rdata_awaiters = []

    def await_replication(self):
        d = Deferred()
        self._rdata_awaiters.append(d)
        return make_deferred_yieldable(d)

    def on_rdata(self, stream_name, token, rows):
        awaiters = self._rdata_awaiters
        self._rdata_awaiters = []
        super(TestReplicationClientHandler, self).on_rdata(stream_name, token, rows)
        with PreserveLoggingContext():
            for a in awaiters:
                a.callback(None)


class BaseSlavedStoreTestCase(unittest.TestCase):
    @defer.inlineCallbacks
    def setUp(self):
        self.hs = yield setup_test_homeserver(
            self.addCleanup,
            "blue",
            http_client=None,
            federation_client=Mock(),
            ratelimiter=NonCallableMock(spec_set=["send_message"]),
        )
        self.hs.get_ratelimiter().send_message.return_value = (True, 0)

        self.master_store = self.hs.get_datastore()
        self.slaved_store = self.STORE_TYPE(self.hs.get_db_conn(), self.hs)
        self.event_id = 0

        server_factory = ReplicationStreamProtocolFactory(self.hs)
        # XXX: mktemp is unsafe and should never be used. but we're just a test.
        path = tempfile.mktemp(prefix="base_slaved_store_test_case_socket")
        listener = reactor.listenUNIX(path, server_factory)
        self.addCleanup(listener.stopListening)
        self.streamer = server_factory.streamer

        self.replication_handler = TestReplicationClientHandler(self.slaved_store)
        client_factory = ReplicationClientFactory(
            self.hs, "client_name", self.replication_handler
        )
        client_connector = reactor.connectUNIX(path, client_factory)
        self.addCleanup(client_factory.stopTrying)
        self.addCleanup(client_connector.disconnect)

    def replicate(self):
        """Tell the master side of replication that something has happened, and then
        wait for the replication to occur.
        """
        # xxx: should we be more specific in what we wait for?
        d = self.replication_handler.await_replication()
        self.streamer.on_notifier_poke()
        return d

    @defer.inlineCallbacks
    def check(self, method, args, expected_result=None):
        master_result = yield getattr(self.master_store, method)(*args)
        slaved_result = yield getattr(self.slaved_store, method)(*args)
        if expected_result is not None:
            self.assertEqual(master_result, expected_result)
            self.assertEqual(slaved_result, expected_result)
        self.assertEqual(master_result, slaved_result)
