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

from synapse.replication.tcp.client import (
    DirectTcpReplicationClientFactory,
    ReplicationDataHandler,
)
from synapse.replication.tcp.handler import ReplicationCommandHandler
from synapse.replication.tcp.resource import ReplicationStreamProtocolFactory
from synapse.storage.database import make_conn

from tests import unittest
from tests.server import FakeTransport


class BaseSlavedStoreTestCase(unittest.HomeserverTestCase):
    def make_homeserver(self, reactor, clock):

        hs = self.setup_test_homeserver(
            "blue",
            federation_client=Mock(),
            ratelimiter=NonCallableMock(spec_set=["can_do_action"]),
        )

        hs.get_ratelimiter().can_do_action.return_value = (True, 0)

        return hs

    def prepare(self, reactor, clock, hs):

        db_config = hs.config.database.get_single_database()
        self.master_store = self.hs.get_datastore()
        self.storage = hs.get_storage()
        database = hs.get_datastores().databases[0]
        self.slaved_store = self.STORE_TYPE(
            database, make_conn(db_config, database.engine), self.hs
        )
        self.event_id = 0

        server_factory = ReplicationStreamProtocolFactory(self.hs)
        self.streamer = hs.get_replication_streamer()

        # We now do some gut wrenching so that we have a client that is based
        # off of the slave store rather than the main store.
        self.replication_handler = ReplicationCommandHandler(self.hs)
        self.replication_handler._instance_name = "worker"
        self.replication_handler._replication_data_handler = ReplicationDataHandler(
            self.slaved_store
        )

        client_factory = DirectTcpReplicationClientFactory(
            self.hs, "client_name", self.replication_handler
        )
        client_factory.handler = self.replication_handler

        server = server_factory.buildProtocol(None)
        client = client_factory.buildProtocol(None)

        client.makeConnection(FakeTransport(server, reactor))

        self.server_to_client_transport = FakeTransport(client, reactor)
        server.makeConnection(self.server_to_client_transport)

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
            self.assertEqual(
                master_result,
                expected_result,
                "Expected master result to be %r but was %r"
                % (expected_result, master_result),
            )
            self.assertEqual(
                slaved_result,
                expected_result,
                "Expected slave result to be %r but was %r"
                % (expected_result, slaved_result),
            )
        self.assertEqual(
            master_result,
            slaved_result,
            "Slave result %r does not match master result %r"
            % (slaved_result, master_result),
        )
