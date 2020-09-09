from mock import Mock

from synapse.rest import admin
from synapse.rest.client.v1 import login, room

from tests.test_utils import event_injection, make_awaitable
from tests.unittest import FederatingHomeserverTestCase, override_config


class FederationCatchUpTestCases(FederatingHomeserverTestCase):
    servlets = [
        admin.register_servlets,
        room.register_servlets,
        login.register_servlets,
    ]

    def make_homeserver(self, reactor, clock):
        return self.setup_test_homeserver(
            federation_transport_client=Mock(spec=["send_transaction"]),
        )

    def prepare(self, reactor, clock, hs):
        # stub out get_current_hosts_in_room
        state_handler = hs.get_state_handler()

        # This mock is crucial for destination_rooms to be populated.
        state_handler.get_current_hosts_in_room = Mock(
            return_value=make_awaitable(["test", "host2"])
        )

        # whenever send_transaction is called, record the pdu data
        self.pdus = []
        self.failed_pdus = []
        self.is_online = True
        self.hs.get_federation_transport_client().send_transaction.side_effect = (
            self.record_transaction
        )

    async def record_transaction(self, txn, json_cb):
        if self.is_online:
            data = json_cb()
            self.pdus.extend(data["pdus"])
            return {}
        else:
            data = json_cb()
            self.failed_pdus.extend(data["pdus"])
            raise IOError("Failed to connect because this is a test!")

    def get_destination_room(self, room: str, destination: str = "host2") -> dict:
        """
        Gets the destination_rooms entry for a (destination, room_id) pair.

        Args:
            room: room ID
            destination: what destination, default is "host2"

        Returns:
            Dictionary of { event_id: str, stream_ordering: int }
        """
        event_id, stream_ordering = self.get_success(
            self.hs.get_datastore().db_pool.execute(
                "test:get_destination_rooms",
                None,
                """
                SELECT event_id, stream_ordering
                    FROM destination_rooms dr
                    JOIN events USING (stream_ordering)
                    WHERE dr.destination = ? AND dr.room_id = ?
                """,
                destination,
                room,
            )
        )[0]
        return {"event_id": event_id, "stream_ordering": stream_ordering}

    @override_config({"send_federation": True})
    def test_catch_up_destination_rooms_tracking(self):
        """
        Tests that we populate the `destination_rooms` table as needed.
        """
        self.register_user("u1", "you the one")
        u1_token = self.login("u1", "you the one")
        room = self.helper.create_room_as("u1", tok=u1_token)

        self.get_success(
            event_injection.inject_member_event(self.hs, room, "@user:host2", "join")
        )

        event_id_1 = self.helper.send(room, "wombats!", tok=u1_token)["event_id"]

        row_1 = self.get_destination_room(room)

        event_id_2 = self.helper.send(room, "rabbits!", tok=u1_token)["event_id"]

        row_2 = self.get_destination_room(room)

        # check: events correctly registered in order
        self.assertEqual(row_1["event_id"], event_id_1)
        self.assertEqual(row_2["event_id"], event_id_2)
        self.assertEqual(row_1["stream_ordering"], row_2["stream_ordering"] - 1)

    @override_config({"send_federation": True})
    def test_catch_up_last_successful_stream_ordering_tracking(self):
        """
        Tests that we populate the `destination_rooms` table as needed.
        """
        self.register_user("u1", "you the one")
        u1_token = self.login("u1", "you the one")
        room = self.helper.create_room_as("u1", tok=u1_token)

        # take the remote offline
        self.is_online = False

        self.get_success(
            event_injection.inject_member_event(self.hs, room, "@user:host2", "join")
        )

        self.helper.send(room, "wombats!", tok=u1_token)
        self.pump()

        lsso_1 = self.get_success(
            self.hs.get_datastore().get_destination_last_successful_stream_ordering(
                "host2"
            )
        )

        self.assertIsNone(
            lsso_1,
            "There should be no last successful stream ordering for an always-offline destination",
        )

        # bring the remote online
        self.is_online = True

        event_id_2 = self.helper.send(room, "rabbits!", tok=u1_token)["event_id"]

        lsso_2 = self.get_success(
            self.hs.get_datastore().get_destination_last_successful_stream_ordering(
                "host2"
            )
        )
        row_2 = self.get_destination_room(room)

        self.assertEqual(
            self.pdus[0]["content"]["body"],
            "rabbits!",
            "Test fault: didn't receive the right PDU",
        )
        self.assertEqual(
            row_2["event_id"],
            event_id_2,
            "Test fault: destination_rooms not updated correctly",
        )
        self.assertEqual(
            lsso_2,
            row_2["stream_ordering"],
            "Send succeeded but not marked as last_successful_stream_ordering",
        )
