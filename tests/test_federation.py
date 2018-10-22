
from mock import Mock

from twisted.internet.defer import maybeDeferred, succeed

from synapse.events import FrozenEvent
from synapse.types import Requester, UserID
from synapse.util import Clock

from tests import unittest
from tests.server import ThreadedMemoryReactorClock, setup_test_homeserver


class MessageAcceptTests(unittest.TestCase):
    def setUp(self):

        self.http_client = Mock()
        self.reactor = ThreadedMemoryReactorClock()
        self.hs_clock = Clock(self.reactor)
        self.homeserver = setup_test_homeserver(
            self.addCleanup,
            http_client=self.http_client,
            clock=self.hs_clock,
            reactor=self.reactor,
        )

        user_id = UserID("us", "test")
        our_user = Requester(user_id, None, False, None, None)
        room_creator = self.homeserver.get_room_creation_handler()
        room = room_creator.create_room(
            our_user, room_creator.PRESETS_DICT["public_chat"], ratelimit=False
        )
        self.reactor.advance(0.1)
        self.room_id = self.successResultOf(room)["room_id"]

        # Figure out what the most recent event is
        most_recent = self.successResultOf(
            maybeDeferred(
                self.homeserver.datastore.get_latest_event_ids_in_room, self.room_id
            )
        )[0]

        join_event = FrozenEvent(
            {
                "room_id": self.room_id,
                "sender": "@baduser:test.serv",
                "state_key": "@baduser:test.serv",
                "event_id": "$join:test.serv",
                "depth": 1000,
                "origin_server_ts": 1,
                "type": "m.room.member",
                "origin": "test.servx",
                "content": {"membership": "join"},
                "auth_events": [],
                "prev_state": [(most_recent, {})],
                "prev_events": [(most_recent, {})],
            }
        )

        self.handler = self.homeserver.get_handlers().federation_handler
        self.handler.do_auth = lambda *a, **b: succeed(True)
        self.client = self.homeserver.get_federation_client()
        self.client._check_sigs_and_hash_and_fetch = lambda dest, pdus, **k: succeed(
            pdus
        )

        # Send the join, it should return None (which is not an error)
        d = self.handler.on_receive_pdu(
            "test.serv", join_event, sent_to_us_directly=True
        )
        self.reactor.advance(1)
        self.assertEqual(self.successResultOf(d), None)

        # Make sure we actually joined the room
        self.assertEqual(
            self.successResultOf(
                maybeDeferred(
                    self.homeserver.datastore.get_latest_event_ids_in_room, self.room_id
                )
            )[0],
            "$join:test.serv",
        )

    def test_cant_hide_direct_ancestors(self):
        """
        If you send a message, you must be able to provide the direct
        prev_events that said event references.
        """

        def post_json(destination, path, data, headers=None, timeout=0):
            # If it asks us for new missing events, give them NOTHING
            if path.startswith("/_matrix/federation/v1/get_missing_events/"):
                return {"events": []}

        self.http_client.post_json = post_json

        # Figure out what the most recent event is
        most_recent = self.successResultOf(
            maybeDeferred(
                self.homeserver.datastore.get_latest_event_ids_in_room, self.room_id
            )
        )[0]

        # Now lie about an event
        lying_event = FrozenEvent(
            {
                "room_id": self.room_id,
                "sender": "@baduser:test.serv",
                "event_id": "one:test.serv",
                "depth": 1000,
                "origin_server_ts": 1,
                "type": "m.room.message",
                "origin": "test.serv",
                "content": "hewwo?",
                "auth_events": [],
                "prev_events": [("two:test.serv", {}), (most_recent, {})],
            }
        )

        d = self.handler.on_receive_pdu(
            "test.serv", lying_event, sent_to_us_directly=True
        )

        # Step the reactor, so the database fetches come back
        self.reactor.advance(1)

        # on_receive_pdu should throw an error
        failure = self.failureResultOf(d)
        self.assertEqual(
            failure.value.args[0],
            (
                "ERROR 403: Your server isn't divulging details about prev_events "
                "referenced in this event."
            ),
        )

        # Make sure the invalid event isn't there
        extrem = maybeDeferred(
            self.homeserver.datastore.get_latest_event_ids_in_room, self.room_id
        )
        self.assertEqual(self.successResultOf(extrem)[0], "$join:test.serv")

    def test_cant_hide_past_history(self):
        """
        If you send a message, you must be able to provide the direct
        prev_events that said event references.
        """

        def post_json(destination, path, data, headers=None, timeout=0):
            if path.startswith("/_matrix/federation/v1/get_missing_events/"):
                return {
                    "events": [
                        {
                            "room_id": self.room_id,
                            "sender": "@baduser:test.serv",
                            "event_id": "three:test.serv",
                            "depth": 1000,
                            "origin_server_ts": 1,
                            "type": "m.room.message",
                            "origin": "test.serv",
                            "content": "hewwo?",
                            "auth_events": [],
                            "prev_events": [("four:test.serv", {})],
                        }
                    ]
                }

        self.http_client.post_json = post_json

        def get_json(destination, path, args, headers=None):
            if path.startswith("/_matrix/federation/v1/state_ids/"):
                d = self.successResultOf(
                    self.homeserver.datastore.get_state_ids_for_event("one:test.serv")
                )

                return succeed(
                    {
                        "pdu_ids": [
                            y
                            for x, y in d.items()
                            if x == ("m.room.member", "@us:test")
                        ],
                        "auth_chain_ids": list(d.values()),
                    }
                )

        self.http_client.get_json = get_json

        # Figure out what the most recent event is
        most_recent = self.successResultOf(
            maybeDeferred(
                self.homeserver.datastore.get_latest_event_ids_in_room, self.room_id
            )
        )[0]

        # Make a good event
        good_event = FrozenEvent(
            {
                "room_id": self.room_id,
                "sender": "@baduser:test.serv",
                "event_id": "one:test.serv",
                "depth": 1000,
                "origin_server_ts": 1,
                "type": "m.room.message",
                "origin": "test.serv",
                "content": "hewwo?",
                "auth_events": [],
                "prev_events": [(most_recent, {})],
            }
        )

        d = self.handler.on_receive_pdu(
            "test.serv", good_event, sent_to_us_directly=True
        )
        self.reactor.advance(1)
        self.assertEqual(self.successResultOf(d), None)

        bad_event = FrozenEvent(
            {
                "room_id": self.room_id,
                "sender": "@baduser:test.serv",
                "event_id": "two:test.serv",
                "depth": 1000,
                "origin_server_ts": 1,
                "type": "m.room.message",
                "origin": "test.serv",
                "content": "hewwo?",
                "auth_events": [],
                "prev_events": [("one:test.serv", {}), ("three:test.serv", {})],
            }
        )

        d = self.handler.on_receive_pdu(
            "test.serv", bad_event, sent_to_us_directly=True
        )
        self.reactor.advance(1)

        extrem = maybeDeferred(
            self.homeserver.datastore.get_latest_event_ids_in_room, self.room_id
        )
        self.assertEqual(self.successResultOf(extrem)[0], "two:test.serv")

        state = self.homeserver.get_state_handler().get_current_state_ids(self.room_id)
        self.reactor.advance(1)
        self.assertIn(("m.room.member", "@us:test"), self.successResultOf(state).keys())
