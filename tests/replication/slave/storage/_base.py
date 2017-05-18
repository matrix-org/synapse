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

from twisted.internet import defer, reactor
from tests import unittest

from mock import Mock, NonCallableMock
from tests.utils import setup_test_homeserver
from synapse.replication.tcp.resource import ReplicationStreamProtocolFactory
from synapse.replication.tcp.client import (
    ReplicationClientHandler, ReplicationClientFactory,
)


class BaseSlavedStoreTestCase(unittest.TestCase):
    @defer.inlineCallbacks
    def setUp(self):
        self.hs = yield setup_test_homeserver(
            "blue",
            http_client=None,
            replication_layer=Mock(),
            ratelimiter=NonCallableMock(spec_set=[
                "send_message",
            ]),
        )
        self.hs.get_ratelimiter().send_message.return_value = (True, 0)

        self.master_store = self.hs.get_datastore()
        self.slaved_store = self.STORE_TYPE(self.hs.get_db_conn(), self.hs)
        self.event_id = 0

        server_factory = ReplicationStreamProtocolFactory(self.hs)
        listener = reactor.listenUNIX("\0xxx", server_factory)
        self.addCleanup(listener.stopListening)
        self.streamer = server_factory.streamer

        self.replication_handler = ReplicationClientHandler(self.slaved_store)
        client_factory = ReplicationClientFactory(
            self.hs, "client_name", self.replication_handler
        )
        client_connector = reactor.connectUNIX("\0xxx", client_factory)
        self.addCleanup(client_factory.stopTrying)
        self.addCleanup(client_connector.disconnect)

    @defer.inlineCallbacks
    def replicate(self):
        yield self.streamer.on_notifier_poke()
        d = self.replication_handler.await_sync("replication_test")
        self.streamer.send_sync_to_all_connections("replication_test")
        yield d

    @defer.inlineCallbacks
    def check(self, method, args, expected_result=None):
        master_result = yield getattr(self.master_store, method)(*args)
        slaved_result = yield getattr(self.slaved_store, method)(*args)
        if expected_result is not None:
            self.assertEqual(master_result, expected_result)
            self.assertEqual(slaved_result, expected_result)
        self.assertEqual(master_result, slaved_result)
