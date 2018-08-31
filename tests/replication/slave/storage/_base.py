# Copyright 2016 OpenMarket Ltd
# Copyright 2018 New Vector Ltd
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

from mock import Mock, NonCallableMock

import attr

from synapse.replication.tcp.client import (
    ReplicationClientFactory,
    ReplicationClientHandler,
)
from synapse.replication.tcp.resource import ReplicationStreamProtocolFactory

from tests import unittest


class BaseSlavedStoreTestCase(unittest.HomeserverTestCase):
    def make_homeserver(self, reactor, clock):

        hs = self.setup_test_homeserver(
            "blue",
            federation_client=Mock(),
            ratelimiter=NonCallableMock(spec_set=["send_message"]),
        )

        hs.get_ratelimiter().send_message.return_value = (True, 0)

        return hs

    def prepare(self, reactor, clock, hs):

        self.master_store = self.hs.get_datastore()
        self.slaved_store = self.STORE_TYPE(self.hs.get_db_conn(), self.hs)
        self.event_id = 0

        server_factory = ReplicationStreamProtocolFactory(self.hs)
        self.streamer = server_factory.streamer

        self.replication_handler = ReplicationClientHandler(self.slaved_store)
        client_factory = ReplicationClientFactory(
            self.hs, "client_name", self.replication_handler
        )

        server = server_factory.buildProtocol(None)
        client = client_factory.buildProtocol(None)

        @attr.s
        class FakeTransport(object):

            other = attr.ib()
            disconnecting = False
            buffer = attr.ib(default=b'')

            def registerProducer(self, producer, streaming):

                self.producer = producer

                def _produce():
                    self.producer.resumeProducing()
                    reactor.callLater(0.1, _produce)

                reactor.callLater(0.0, _produce)

            def write(self, byt):
                self.buffer = self.buffer + byt

                if getattr(self.other, "transport") is not None:
                    self.other.dataReceived(self.buffer)
                    self.buffer = b""

            def writeSequence(self, seq):
                for x in seq:
                    self.write(x)

        client.makeConnection(FakeTransport(server))
        server.makeConnection(FakeTransport(client))

    def replicate(self):
        """Tell the master side of replication that something has happened, and then
        wait for the replication to occur.
        """
        self.streamer.on_notifier_poke()
        self.pump(0.1)

    def check(self, method, args, expected_result=None):
        master_result = self.get_success(getattr(self.master_store, method)(*args))
        slaved_result = self.get_success(getattr(self.slaved_store, method)(*args))
        if expected_result is not None:
            self.assertEqual(master_result, expected_result)
            self.assertEqual(slaved_result, expected_result)
        self.assertEqual(master_result, slaved_result)
