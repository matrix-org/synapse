# Copyright 2014 OpenMarket Ltd
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

# trial imports
from twisted.internet import defer
from tests import unittest

# python imports
from mock import Mock, ANY

from ..utils import MockHttpResource, MockClock, setup_test_homeserver

from synapse.federation import initialize_http_replication
from synapse.events import FrozenEvent

from synapse.storage.transactions import DestinationsTable


def make_pdu(prev_pdus=[], **kwargs):
    """Provide some default fields for making a PduTuple."""
    pdu_fields = {
        "state_key": None,
        "prev_events": prev_pdus,
    }
    pdu_fields.update(kwargs)

    return FrozenEvent(pdu_fields)


class FederationTestCase(unittest.TestCase):
    @defer.inlineCallbacks
    def setUp(self):
        self.mock_resource = MockHttpResource()
        self.mock_http_client = Mock(spec=[
            "get_json",
            "put_json",
        ])
        self.mock_persistence = Mock(spec=[
            "prep_send_transaction",
            "delivered_txn",
            "get_received_txn_response",
            "set_received_txn_response",
            "get_destination_retry_timings",
            "get_auth_chain",
        ])
        self.mock_persistence.get_received_txn_response.return_value = (
            defer.succeed(None)
        )
        self.mock_persistence.get_destination_retry_timings.return_value = (
            defer.succeed(DestinationsTable.EntryType("", 0, 0))
        )
        self.mock_persistence.get_auth_chain.return_value = []
        self.clock = MockClock()
        hs = yield setup_test_homeserver(
            resource_for_federation=self.mock_resource,
            http_client=self.mock_http_client,
            datastore=self.mock_persistence,
            clock=self.clock,
            keyring=Mock(),
        )
        self.federation = initialize_http_replication(hs)
        self.distributor = hs.get_distributor()

    @defer.inlineCallbacks
    def test_get_state(self):
        mock_handler = Mock(spec=[
            "get_state_for_pdu",
        ])

        self.federation.set_handler(mock_handler)

        mock_handler.get_state_for_pdu.return_value = defer.succeed([])

        # Empty context initially
        (code, response) = yield self.mock_resource.trigger(
            "GET",
            "/_matrix/federation/v1/state/my-context/",
            None
        )
        self.assertEquals(200, code)
        self.assertFalse(response["pdus"])

        # Now lets give the context some state
        mock_handler.get_state_for_pdu.return_value = (
            defer.succeed([
                make_pdu(
                    event_id="the-pdu-id",
                    origin="red",
                    user_id="@a:red",
                    room_id="my-context",
                    type="m.topic",
                    origin_server_ts=123456789000,
                    depth=1,
                    content={"topic": "The topic"},
                    state_key="",
                    power_level=1000,
                    prev_state="last-pdu-id",
                ),
            ])
        )

        (code, response) = yield self.mock_resource.trigger(
            "GET",
            "/_matrix/federation/v1/state/my-context/",
            None
        )
        self.assertEquals(200, code)
        self.assertEquals(1, len(response["pdus"]))

    @defer.inlineCallbacks
    def test_get_pdu(self):
        mock_handler = Mock(spec=[
            "get_persisted_pdu",
        ])

        self.federation.set_handler(mock_handler)

        mock_handler.get_persisted_pdu.return_value = (
            defer.succeed(None)
        )

        (code, response) = yield self.mock_resource.trigger(
            "GET",
            "/_matrix/federation/v1/event/abc123def456/",
            None
        )
        self.assertEquals(404, code)

        # Now insert such a PDU
        mock_handler.get_persisted_pdu.return_value = (
            defer.succeed(
                make_pdu(
                    event_id="abc123def456",
                    origin="red",
                    user_id="@a:red",
                    room_id="my-context",
                    type="m.text",
                    origin_server_ts=123456789001,
                    depth=1,
                    content={"text": "Here is the message"},
                )
            )
        )

        (code, response) = yield self.mock_resource.trigger(
            "GET",
            "/_matrix/federation/v1/event/abc123def456/",
            None
        )
        self.assertEquals(200, code)
        self.assertEquals(1, len(response["pdus"]))
        self.assertEquals("m.text", response["pdus"][0]["type"])

    @defer.inlineCallbacks
    def test_send_pdu(self):
        self.mock_http_client.put_json.return_value = defer.succeed(
            (200, "OK")
        )

        pdu = make_pdu(
            event_id="abc123def456",
            origin="red",
            user_id="@a:red",
            room_id="my-context",
            type="m.text",
            origin_server_ts=123456789001,
            depth=1,
            content={"text": "Here is the message"},
        )

        yield self.federation.send_pdu(pdu, ["remote"])

        self.mock_http_client.put_json.assert_called_with(
            "remote",
            path="/_matrix/federation/v1/send/1000000/",
            data={
                "origin_server_ts": 1000000,
                "origin": "test",
                "pdus": [
                    pdu.get_pdu_json(),
                ],
                'pdu_failures': [],
            },
            json_data_callback=ANY,
        )

    @defer.inlineCallbacks
    def test_send_edu(self):
        self.mock_http_client.put_json.return_value = defer.succeed(
            (200, "OK")
        )

        yield self.federation.send_edu(
            destination="remote",
            edu_type="m.test",
            content={"testing": "content here"},
        )

        # MockClock ensures we can guess these timestamps
        self.mock_http_client.put_json.assert_called_with(
            "remote",
            path="/_matrix/federation/v1/send/1000000/",
            data={
                "origin": "test",
                "origin_server_ts": 1000000,
                "pdus": [],
                "edus": [
                    {
                        "edu_type": "m.test",
                        "content": {"testing": "content here"},
                    }
                ],
                'pdu_failures': [],
            },
            json_data_callback=ANY,
        )

    @defer.inlineCallbacks
    def test_recv_edu(self):
        recv_observer = Mock()
        recv_observer.return_value = defer.succeed(())

        self.federation.register_edu_handler("m.test", recv_observer)

        yield self.mock_resource.trigger(
            "PUT",
            "/_matrix/federation/v1/send/1001000/",
            """{
                "origin": "remote",
                "origin_server_ts": 1001000,
                "pdus": [],
                "edus": [
                    {
                        "origin": "remote",
                        "destination": "test",
                        "edu_type": "m.test",
                        "content": {"testing": "reply here"}
                    }
                ]
            }"""
        )

        recv_observer.assert_called_with(
            "remote", {"testing": "reply here"}
        )

    @defer.inlineCallbacks
    def test_send_query(self):
        self.mock_http_client.get_json.return_value = defer.succeed(
            {"your": "response"}
        )

        response = yield self.federation.make_query(
            destination="remote",
            query_type="a-question",
            args={"one": "1", "two": "2"},
        )

        self.assertEquals({"your": "response"}, response)

        self.mock_http_client.get_json.assert_called_with(
            destination="remote",
            path="/_matrix/federation/v1/query/a-question",
            args={"one": "1", "two": "2"},
            retry_on_dns_fail=True,
        )

    @defer.inlineCallbacks
    def test_recv_query(self):
        recv_handler = Mock()
        recv_handler.return_value = defer.succeed({"another": "response"})

        self.federation.register_query_handler("a-question", recv_handler)

        code, response = yield self.mock_resource.trigger(
            "GET",
            "/_matrix/federation/v1/query/a-question?three=3&four=4",
            None
        )

        self.assertEquals(200, code)
        self.assertEquals({"another": "response"}, response)

        recv_handler.assert_called_with(
            {"three": "3", "four": "4"}
        )
