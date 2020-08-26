from typing import List, Tuple

from mock import Mock

from twisted.internet import defer

from synapse.events import EventBase
from synapse.federation.sender import PerDestinationQueue, TransactionManager
from synapse.federation.units import Edu
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

    def get_destination_room(self, room: str, destination: str = "host2") -> dict:
        """
        Gets the destination_rooms entry for a (destination, room_id) pair.

        Args:
            room: room ID
            destination: what destination, default is "host2"

        Returns:
            Dictionary of { event_id: str, stream_ordering: int }
        """
        return self.get_success(
            self.hs.get_datastore().db_pool.simple_select_one(
                table="destination_rooms",
                keyvalues={"destination": destination, "room_id": room},
                retcols=["event_id", "stream_ordering"],
            )
        )

    def make_fake_destination_queue(
        self, destination: str = "host2"
    ) -> Tuple[PerDestinationQueue, List[EventBase]]:
        """
        Makes a fake per-destination queue.
        """
        transaction_manager = TransactionManager(self.hs)
        per_dest_queue = PerDestinationQueue(self.hs, transaction_manager, destination)
        results_list = []

        async def fake_send(
            destination_tm: str,
            pending_pdus: List[Tuple[EventBase, int]],
            _pending_edus: List[Edu],
        ):
            assert destination == destination_tm
            results_list.extend([row[0] for row in pending_pdus])

        transaction_manager.send_new_transaction = fake_send

        return per_dest_queue, results_list

    def record_transaction(self, txn, json_cb):
        if self.is_online:
            data = json_cb()
            self.pdus.extend(data["pdus"])
            return defer.succeed({})
        else:
            data = json_cb()
            self.failed_pdus.extend(data["pdus"])
            return defer.fail(IOError("Failed to connect because this is a test!"))

    @override_config({"send_federation": True})  # critical (1) to federate
    def test_catch_up_from_blank_state(self):
        """
        Runs an overall test of federation catch-up from scratch.
        Further tests will focus on more narrow aspects and edge-cases, but I
        hope to provide an overall view with this test.
        """
        # bring the other server online
        self.is_online = True

        # let's make some events for the other server to receive
        self.register_user("u1", "you the one")
        u1_token = self.login("u1", "you the one")
        room_1 = self.helper.create_room_as("u1", tok=u1_token)
        room_2 = self.helper.create_room_as("u1", tok=u1_token)

        # also critical (2) to federate
        self.get_success(
            event_injection.inject_member_event(self.hs, room_1, "@user:host2", "join")
        )
        self.get_success(
            event_injection.inject_member_event(self.hs, room_2, "@user:host2", "join")
        )

        self.helper.send_state(
            room_1, event_type="m.room.topic", body={"topic": "wombat"}, tok=u1_token
        )

        # check: PDU received for topic event
        self.assertEqual(len(self.pdus), 1)
        self.assertEqual(self.pdus[0]["type"], "m.room.topic")

        # take the remote offline
        self.is_online = False

        # send another event
        self.helper.send(room_1, "hi user!", tok=u1_token)

        # check: things didn't go well since the remote is down
        self.assertEqual(len(self.failed_pdus), 1)
        self.assertEqual(self.failed_pdus[0]["content"]["body"], "hi user!")

        # let's delete the federation transmission queue
        # (this pretends we are starting up fresh.)
        self.assertFalse(
            self.hs.get_federation_sender()
            ._per_destination_queues["host2"]
            .transmission_loop_running
        )
        del self.hs.get_federation_sender()._per_destination_queues["host2"]

        # let's also clear any backoffs
        self.get_success(
            self.hs.get_datastore().set_destination_retry_timings("host2", None, 0, 0)
        )

        # bring the remote online and clear the received pdu list
        self.is_online = True
        self.pdus = []

        # now we need to initiate a federation transaction somehow…
        # to do that, let's send another event (because it's simple to do)
        # (do it to another room otherwise the catch-up logic decides it doesn't
        # need to catch up room_1 — something I overlooked when first writing
        # this test)
        self.helper.send(room_2, "wombats!", tok=u1_token)

        # we should now have received both PDUs
        self.assertEqual(len(self.pdus), 2)
        self.assertEqual(self.pdus[0]["content"]["body"], "hi user!")
        self.assertEqual(self.pdus[1]["content"]["body"], "wombats!")

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

        self.helper.send(room, "wombats!", tok=u1_token)["event_id"]

        self.pump()

        lsso_1 = self.get_success(
            self.hs.get_datastore().get_destination_last_successful_stream_ordering("host2")
        )

        self.assertIsNone(
            lsso_1,
            "There should be no last successful stream ordering for an always-offline destination",
        )

        # bring the remote offline
        self.is_online = True

        event_id_2 = self.helper.send(room, "rabbits!", tok=u1_token)["event_id"]

        lsso_2 = self.get_success(
            self.hs.get_datastore().get_destination_last_successful_stream_ordering("host2")
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

    @override_config({"send_federation": True})
    def test_catch_up_loop_no_pdus_in_main_queue(self):
        """
        Tests, somewhat more synthetically, behaviour of
        _catch_up_transmission_loop when there aren't any PDUs in the main queue.
        """

        # ARRANGE
        per_dest_queue, sent_pdus = self.make_fake_destination_queue()

        self.register_user("u1", "you the one")
        u1_token = self.login("u1", "you the one")
        room_1 = self.helper.create_room_as("u1", tok=u1_token)
        room_2 = self.helper.create_room_as("u1", tok=u1_token)
        room_3 = self.helper.create_room_as("u1", tok=u1_token)
        self.get_success(
            event_injection.inject_member_event(self.hs, room_1, "@user:host2", "join")
        )
        self.get_success(
            event_injection.inject_member_event(self.hs, room_2, "@user:host2", "join")
        )
        self.get_success(
            event_injection.inject_member_event(self.hs, room_3, "@user:host2", "join")
        )

        # create some events to play with

        self.helper.send(room_1, "you hear me!!", tok=u1_token)
        event_id_2 = self.helper.send(room_2, "wombats!", tok=u1_token)["event_id"]
        self.helper.send(room_3, "Matrix!", tok=u1_token)
        event_id_4 = self.helper.send(room_2, "rabbits!", tok=u1_token)["event_id"]
        event_id_5 = self.helper.send(room_3, "Synapse!", tok=u1_token)["event_id"]

        # destination_rooms should already be populated, but let us pretend that we already
        # delivered up to and including event id 2

        event_2 = self.get_success(self.hs.get_datastore().get_event(event_id_2))

        self.get_success(
            self.hs.get_datastore().set_destination_last_successful_stream_ordering(
                "host2", event_2.internal_metadata.stream_ordering
            )
        )

        # ACT
        self.get_success(per_dest_queue._catch_up_transmission_loop())

        # ASSERT, noticing in particular:
        # - event 3 not sent out, because event 5 replaces it
        # - order is least recent first, so event 5 comes after event 4
        self.assertEqual(len(sent_pdus), 2)
        self.assertEqual(sent_pdus[0].event_id, event_id_4)
        self.assertEqual(sent_pdus[1].event_id, event_id_5)

    @override_config({"send_federation": True})
    def test_catch_up_loop_with_pdus_in_main_queue(self):
        """
        Tests, somewhat more synthetically, behaviour of
        _catch_up_transmission_loop when there aren't any PDUs in the main queue.
        """

        # ARRANGE
        per_dest_queue, sent_pdus = self.make_fake_destination_queue()

        self.register_user("u1", "you the one")
        u1_token = self.login("u1", "you the one")
        room_1 = self.helper.create_room_as("u1", tok=u1_token)
        room_2 = self.helper.create_room_as("u1", tok=u1_token)
        room_3 = self.helper.create_room_as("u1", tok=u1_token)
        self.get_success(
            event_injection.inject_member_event(self.hs, room_1, "@user:host2", "join")
        )
        self.get_success(
            event_injection.inject_member_event(self.hs, room_2, "@user:host2", "join")
        )
        self.get_success(
            event_injection.inject_member_event(self.hs, room_3, "@user:host2", "join")
        )

        # create some events to play with

        self.helper.send(room_1, "you hear me!!", tok=u1_token)
        event_id_2 = self.helper.send(room_2, "wombats!", tok=u1_token)["event_id"]
        self.helper.send(room_3, "Matrix!", tok=u1_token)
        event_id_4 = self.helper.send(room_2, "rabbits!", tok=u1_token)["event_id"]
        event_id_5 = self.helper.send(room_3, "Synapse!", tok=u1_token)["event_id"]

        # put event 5 in the main queue — assume it's the cause of us triggering a
        # catch-up (or is otherwise sent after retry backoff ends).
        # (Block the transmission loop from running by marking it as already
        #  running, because we manually invoke the catch-up loop for testing
        #  purposes.)
        per_dest_queue.transmission_loop_running = True
        event_5 = self.get_success(self.hs.get_datastore().get_event(event_id_5))
        per_dest_queue.send_pdu(event_5, 1)

        # destination_rooms should already be populated, but let us pretend that we already
        # delivered up to and including event id 2

        event_2 = self.get_success(self.hs.get_datastore().get_event(event_id_2))

        self.get_success(
            self.hs.get_datastore().set_destination_last_successful_stream_ordering(
                "host2", event_2.internal_metadata.stream_ordering
            )
        )

        # ACT
        self.get_success(per_dest_queue._catch_up_transmission_loop())

        # ASSERT, noticing in particular:
        # - event 3 not sent out, because event 5 replaces it
        # - event 5 is not sent out, because it's already in our main PDU queue
        self.assertEqual(len(sent_pdus), 1)
        self.assertEqual(sent_pdus[0].event_id, event_id_4)
