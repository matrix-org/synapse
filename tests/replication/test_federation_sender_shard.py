# -*- coding: utf-8 -*-
# Copyright 2019 New Vector Ltd
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
import logging

from mock import Mock

from twisted.internet import defer

from synapse.api.constants import EventTypes, Membership
from synapse.app.generic_worker import GenericWorkerServer
from synapse.events.builder import EventBuilderFactory
from synapse.replication.http import streams
from synapse.replication.tcp.handler import ReplicationCommandHandler
from synapse.replication.tcp.protocol import ClientReplicationStreamProtocol
from synapse.replication.tcp.resource import ReplicationStreamProtocolFactory
from synapse.rest.admin import register_servlets_for_client_rest_resource
from synapse.rest.client.v1 import login, room
from synapse.types import UserID

from tests import unittest
from tests.server import FakeTransport

logger = logging.getLogger(__name__)


class BaseStreamTestCase(unittest.HomeserverTestCase):
    """Base class for tests of the replication streams"""

    servlets = [
        streams.register_servlets,
    ]

    def prepare(self, reactor, clock, hs):
        # build a replication server
        self.server_factory = ReplicationStreamProtocolFactory(hs)
        self.streamer = hs.get_replication_streamer()

        store = hs.get_datastore()
        self.database = store.db

        # Make a new HomeServer object for the worker
        self.reactor.lookups["testserv"] = "1.2.3.4"

    def default_config(self):
        conf = super().default_config()
        conf["send_federation"] = False
        return conf

    def make_worker_hs(self, extra_config={}):
        config = self._get_worker_hs_config()
        config.update(extra_config)

        mock_federation_client = Mock(spec=["put_json"])
        mock_federation_client.put_json.side_effect = lambda *_, **__: defer.succeed({})

        worker_hs = self.setup_test_homeserver(
            http_client=mock_federation_client,
            homeserverToUse=GenericWorkerServer,
            config=config,
            reactor=self.reactor,
        )

        store = worker_hs.get_datastore()
        store.db._db_pool = self.database._db_pool

        self.get_success(
            store.db.runInteraction("reset", store._reset_federation_positions_txn)
        )

        repl_handler = ReplicationCommandHandler(worker_hs)
        client = ClientReplicationStreamProtocol(
            worker_hs, "client", "test", self.clock, repl_handler,
        )
        server = self.server_factory.buildProtocol(None)

        client_transport = FakeTransport(server, self.reactor)
        client.makeConnection(client_transport)

        server_transport = FakeTransport(client, self.reactor)
        server.makeConnection(server_transport)

        return worker_hs

    def _get_worker_hs_config(self) -> dict:
        config = self.default_config()
        config["worker_app"] = "synapse.app.federation_sender"
        config["worker_replication_host"] = "testserv"
        config["worker_replication_http_port"] = "8765"
        return config

    def replicate(self):
        """Tell the master side of replication that something has happened, and then
        wait for the replication to occur.
        """
        self.streamer.on_notifier_poke()
        self.pump()

    def create_room_with_remote_server(self, user, token, remote_server="other_server"):
        room = self.helper.create_room_as(user, tok=token)
        store = self.hs.get_datastore()
        federation = self.hs.get_handlers().federation_handler

        prev_event_ids = self.get_success(store.get_latest_event_ids_in_room(room))
        room_version = self.get_success(store.get_room_version(room))

        factory = EventBuilderFactory(self.hs)
        factory.hostname = remote_server

        user_id = UserID("user", remote_server).to_string()

        event_dict = {
            "type": EventTypes.Member,
            "state_key": user_id,
            "content": {"membership": Membership.JOIN},
            "sender": user_id,
            "room_id": room,
        }

        builder = factory.for_room_version(room_version, event_dict)
        join_event = self.get_success(builder.build(prev_event_ids))

        self.get_success(federation.on_send_join_request(remote_server, join_event))
        self.replicate()

        return room


class FederationSenderTestCase(BaseStreamTestCase):
    servlets = [
        login.register_servlets,
        register_servlets_for_client_rest_resource,
        room.register_servlets,
    ]

    def test_send_event_single_sender(self):
        worker_hs = self.make_worker_hs({"send_federation": True})
        mock_client = worker_hs.get_http_client()

        user = self.register_user("user", "pass")
        token = self.login("user", "pass")

        room = self.create_room_with_remote_server(user, token)

        mock_client.put_json.reset_mock()

        self.create_and_send_event(room, UserID.from_string(user))
        self.replicate()

        # Assert that the event was sent out over federation.
        mock_client.put_json.assert_called()
        self.assertEqual(mock_client.put_json.call_args[0][0], "other_server")
        self.assertTrue(mock_client.put_json.call_args[1]["data"].get("pdus"))

    def test_send_event_sharded(self):
        worker1 = self.make_worker_hs(
            {
                "send_federation": True,
                "worker_name": "sender1",
                "federation_sender_instances": ["sender1", "sender2"],
            }
        )
        mock_client1 = worker1.get_http_client()

        worker2 = self.make_worker_hs(
            {
                "send_federation": True,
                "worker_name": "sender2",
                "federation_sender_instances": ["sender1", "sender2"],
            }
        )
        mock_client2 = worker2.get_http_client()

        user = self.register_user("user2", "pass")
        token = self.login("user2", "pass")

        sent_on_1 = False
        sent_on_2 = False
        for i in range(20):
            server_name = "other_server_%d" % (i,)
            room = self.create_room_with_remote_server(user, token, server_name)
            mock_client1.reset_mock()
            mock_client2.reset_mock()

            self.create_and_send_event(room, UserID.from_string(user))
            self.replicate()

            if mock_client1.put_json.called:
                sent_on_1 = True
                mock_client2.put_json.assert_not_called()
                self.assertEqual(mock_client1.put_json.call_args[0][0], server_name)
                self.assertTrue(mock_client1.put_json.call_args[1]["data"].get("pdus"))
            elif mock_client2.put_json.called:
                sent_on_2 = True
                mock_client1.put_json.assert_not_called()
                self.assertEqual(mock_client2.put_json.call_args[0][0], server_name)
                self.assertTrue(mock_client2.put_json.call_args[1]["data"].get("pdus"))
            else:
                raise AssertionError(
                    "Expected send transaction from one or the other sender"
                )

            if sent_on_1 and sent_on_2:
                break

        self.assertTrue(sent_on_1)
        self.assertTrue(sent_on_2)

    def test_send_typing_sharded(self):
        worker1 = self.make_worker_hs(
            {
                "send_federation": True,
                "worker_name": "sender1",
                "federation_sender_instances": ["sender1", "sender2"],
            }
        )
        mock_client1 = worker1.get_http_client()

        worker2 = self.make_worker_hs(
            {
                "send_federation": True,
                "worker_name": "sender2",
                "federation_sender_instances": ["sender1", "sender2"],
            }
        )
        mock_client2 = worker2.get_http_client()

        user = self.register_user("user3", "pass")
        token = self.login("user3", "pass")

        typing_handler = self.hs.get_typing_handler()

        sent_on_1 = False
        sent_on_2 = False
        for i in range(20):
            server_name = "other_server_%d" % (i,)
            room = self.create_room_with_remote_server(user, token, server_name)
            mock_client1.reset_mock()
            mock_client2.reset_mock()

            self.get_success(
                typing_handler.started_typing(
                    target_user=UserID.from_string(user),
                    auth_user=UserID.from_string(user),
                    room_id=room,
                    timeout=20000,
                )
            )

            self.replicate()

            if mock_client1.put_json.called:
                sent_on_1 = True
                mock_client2.put_json.assert_not_called()
                self.assertEqual(mock_client1.put_json.call_args[0][0], server_name)
                self.assertTrue(mock_client1.put_json.call_args[1]["data"].get("edus"))
            elif mock_client2.put_json.called:
                sent_on_2 = True
                mock_client1.put_json.assert_not_called()
                self.assertEqual(mock_client2.put_json.call_args[0][0], server_name)
                self.assertTrue(mock_client2.put_json.call_args[1]["data"].get("edus"))
            else:
                raise AssertionError(
                    "Expected send transaction from one or the other sender"
                )

            if sent_on_1 and sent_on_2:
                break

        self.assertTrue(sent_on_1)
        self.assertTrue(sent_on_2)
