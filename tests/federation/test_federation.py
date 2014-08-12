# trial imports
from twisted.internet import defer
from twisted.trial import unittest

# python imports
from mock import Mock
import logging

from ..utils import MockHttpServer

from synapse.server import HomeServer
from synapse.federation import initialize_http_replication
from synapse.federation.units import Pdu
from synapse.storage.pdu import PduTuple, PduEntry


logging.getLogger().addHandler(logging.NullHandler())


def make_pdu(prev_pdus=[], **kwargs):
    """Provide some default fields for making a PduTuple."""
    pdu_fields = {
        "is_state": False,
        "unrecognized_keys": [],
        "outlier": False,
        "have_processed": True,
        "state_key": None,
        "power_level": None,
        "prev_state_id": None,
        "prev_state_origin": None,
    }
    pdu_fields.update(kwargs)

    return PduTuple(PduEntry(**pdu_fields), prev_pdus)


class MockClock(object):
    now = 1000

    def time(self):
        return self.now

    def time_msec(self):
        return self.time() * 1000


class FederationTestCase(unittest.TestCase):
    def setUp(self):
        self.mock_http_server = MockHttpServer()
        self.mock_http_client = Mock(spec=[
            "put_json",
        ])
        self.mock_persistence = Mock(spec=[
            "get_current_state_for_context",
            "get_pdu",
            "persist_pdu",
            "update_min_depth_for_context",
            "prep_send_transaction",
            "delivered_txn",
            "get_received_txn_response",
            "set_received_txn_response",
        ])
        self.mock_persistence.get_received_txn_response.return_value = (
                defer.succeed(None)
        )
        self.clock = MockClock()
        hs = HomeServer("test",
                http_server=self.mock_http_server,
                http_client=self.mock_http_client,
                db_pool=None,
                datastore=self.mock_persistence,
                clock=self.clock,
        )
        self.federation = initialize_http_replication(hs)
        self.distributor = hs.get_distributor()

    @defer.inlineCallbacks
    def test_get_state(self):
        self.mock_persistence.get_current_state_for_context.return_value = (
            defer.succeed([])
        )

        # Empty context initially
        (code, response) = yield self.mock_http_server.trigger("GET",
                "/state/my-context/", None)
        self.assertEquals(200, code)
        self.assertFalse(response["pdus"])

        # Now lets give the context some state
        self.mock_persistence.get_current_state_for_context.return_value = (
            defer.succeed([
                make_pdu(
                    pdu_id="the-pdu-id",
                    origin="red",
                    context="my-context",
                    pdu_type="m.topic",
                    ts=123456789000,
                    depth=1,
                    is_state=True,
                    content_json='{"topic":"The topic"}',
                    state_key="",
                    power_level=1000,
                    prev_state_id="last-pdu-id",
                    prev_state_origin="blue",
                ),
            ])
        )

        (code, response) = yield self.mock_http_server.trigger("GET",
                "/state/my-context/", None)
        self.assertEquals(200, code)
        self.assertEquals(1, len(response["pdus"]))

    @defer.inlineCallbacks
    def test_get_pdu(self):
        self.mock_persistence.get_pdu.return_value = (
            defer.succeed(None)
        )

        (code, response) = yield self.mock_http_server.trigger("GET",
                "/pdu/red/abc123def456/", None)
        self.assertEquals(404, code)

        # Now insert such a PDU
        self.mock_persistence.get_pdu.return_value = (
            defer.succeed(
                make_pdu(
                    pdu_id="abc123def456",
                    origin="red",
                    context="my-context",
                    pdu_type="m.text",
                    ts=123456789001,
                    depth=1,
                    content_json='{"text":"Here is the message"}',
                )
            )
        )

        (code, response) = yield self.mock_http_server.trigger("GET",
                "/pdu/red/abc123def456/", None)
        self.assertEquals(200, code)
        self.assertEquals(1, len(response["pdus"]))
        self.assertEquals("m.text", response["pdus"][0]["pdu_type"])

    @defer.inlineCallbacks
    def test_send_pdu(self):
        self.mock_http_client.put_json.return_value = defer.succeed(
                (200, "OK")
        )

        pdu = Pdu(
                pdu_id="abc123def456",
                origin="red",
                destinations=["remote"],
                context="my-context",
                ts=123456789002,
                pdu_type="m.test",
                content={"testing": "content here"},
                depth=1,
        )

        yield self.federation.send_pdu(pdu)

        self.mock_http_client.put_json.assert_called_with(
                "remote",
                path="/send/1000000/",
                data={
                    "ts": 1000000,
                    "origin": "test",
                    "pdus": [
                        {
                            "origin": "red",
                            "pdu_id": "abc123def456",
                            "prev_pdus": [],
                            "ts": 123456789002,
                            "context": "my-context",
                            "pdu_type": "m.test",
                            "is_state": False,
                            "content": {"testing": "content here"},
                            "depth": 1,
                        },
                    ]
                }
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
                path="/send/1000000/",
                data={
                    "origin": "test",
                    "ts": 1000000,
                    "pdus": [],
                    "edus": [
                        {
                            "origin": "test",
                            "destination": "remote",
                            "edu_type": "m.test",
                            "content": {"testing": "content here"},
                        }
                    ],
                })

    @defer.inlineCallbacks
    def test_recv_edu(self):
        recv_observer = Mock()
        recv_observer.return_value = defer.succeed(())

        self.federation.register_edu_handler("m.test", recv_observer)

        yield self.mock_http_server.trigger("PUT", "/send/1001000/",
                """{
                    "origin": "remote",
                    "ts": 1001000,
                    "pdus": [],
                    "edus": [
                        {
                            "origin": "remote",
                            "destination": "test",
                            "edu_type": "m.test",
                            "content": {"testing": "reply here"}
                        }
                    ]
                }""")

        recv_observer.assert_called_with(
                "remote", {"testing": "reply here"}
        )
