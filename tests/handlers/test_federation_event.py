# Copyright 2022 The Matrix.org Foundation C.I.C.
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
from unittest import mock

from synapse.events import make_event_from_dict
from synapse.events.snapshot import EventContext
from synapse.federation.transport.client import StateRequestResponse
from synapse.logging.context import LoggingContext
from synapse.rest import admin
from synapse.rest.client import login, room

from tests import unittest
from tests.test_utils import event_injection, make_awaitable


class FederationEventHandlerTests(unittest.FederatingHomeserverTestCase):
    servlets = [
        admin.register_servlets,
        login.register_servlets,
        room.register_servlets,
    ]

    def make_homeserver(self, reactor, clock):
        # mock out the federation transport client
        self.mock_federation_transport_client = mock.Mock(
            spec=["get_room_state_ids", "get_room_state", "get_event"]
        )
        return super().setup_test_homeserver(
            federation_transport_client=self.mock_federation_transport_client
        )

    def test_process_pulled_event_with_missing_state(self) -> None:
        """Ensure that we correctly handle pulled events with lots of missing state

        In this test, we pretend we are processing a "pulled" event (eg, via backfill
        or get_missing_events). The pulled event has a prev_event we haven't previously
        seen, so the server requests the state at that prev_event. There is a lot
        of state we don't have, so we expect the server to make a /state request.

        We check that the pulled event is correctly persisted, and that the state is
        as we expect.
        """
        return self._test_process_pulled_event_with_missing_state(False)

    def test_process_pulled_event_with_missing_state_where_prev_is_outlier(
        self,
    ) -> None:
        """Ensure that we correctly handle pulled events with lots of missing state

        A slight modification to test_process_pulled_event_with_missing_state. Again
        we have a "pulled" event which refers to a prev_event with lots of state,
        but in this case we already have the prev_event (as an outlier, obviously -
        if it were a regular event, we wouldn't need to request the state).
        """
        return self._test_process_pulled_event_with_missing_state(True)

    def _test_process_pulled_event_with_missing_state(
        self, prev_exists_as_outlier: bool
    ) -> None:
        OTHER_USER = f"@user:{self.OTHER_SERVER_NAME}"
        main_store = self.hs.get_datastores().main
        state_storage_controller = self.hs.get_storage_controllers().state

        # create the room
        user_id = self.register_user("kermit", "test")
        tok = self.login("kermit", "test")
        room_id = self.helper.create_room_as(room_creator=user_id, tok=tok)
        room_version = self.get_success(main_store.get_room_version(room_id))

        # allow the remote user to send state events
        self.helper.send_state(
            room_id,
            "m.room.power_levels",
            {"events_default": 0, "state_default": 0},
            tok=tok,
        )

        # add the remote user to the room
        member_event = self.get_success(
            event_injection.inject_member_event(self.hs, room_id, OTHER_USER, "join")
        )

        initial_state_map = self.get_success(
            main_store.get_partial_current_state_ids(room_id)
        )

        auth_event_ids = [
            initial_state_map[("m.room.create", "")],
            initial_state_map[("m.room.power_levels", "")],
            member_event.event_id,
        ]

        # mock up a load of state events which we are missing
        state_events = [
            make_event_from_dict(
                self.add_hashes_and_signatures(
                    {
                        "type": "test_state_type",
                        "state_key": f"state_{i}",
                        "room_id": room_id,
                        "sender": OTHER_USER,
                        "prev_events": [member_event.event_id],
                        "auth_events": auth_event_ids,
                        "origin_server_ts": 1,
                        "depth": 10,
                        "content": {"body": f"state_{i}"},
                    }
                ),
                room_version,
            )
            for i in range(1, 10)
        ]

        # this is the state that we are going to claim is active at the prev_event.
        state_at_prev_event = state_events + self.get_success(
            main_store.get_events_as_list(initial_state_map.values())
        )

        # mock up a prev event.
        # Depending on the test, we either persist this upfront (as an outlier),
        # or let the server request it.
        prev_event = make_event_from_dict(
            self.add_hashes_and_signatures(
                {
                    "type": "test_regular_type",
                    "room_id": room_id,
                    "sender": OTHER_USER,
                    "prev_events": [],
                    "auth_events": auth_event_ids,
                    "origin_server_ts": 1,
                    "depth": 11,
                    "content": {"body": "missing_prev"},
                }
            ),
            room_version,
        )
        if prev_exists_as_outlier:
            prev_event.internal_metadata.outlier = True
            persistence = self.hs.get_storage_controllers().persistence
            self.get_success(
                persistence.persist_event(
                    prev_event,
                    EventContext.for_outlier(self.hs.get_storage_controllers()),
                )
            )
        else:

            async def get_event(destination: str, event_id: str, timeout=None):
                self.assertEqual(destination, self.OTHER_SERVER_NAME)
                self.assertEqual(event_id, prev_event.event_id)
                return {"pdus": [prev_event.get_pdu_json()]}

            self.mock_federation_transport_client.get_event.side_effect = get_event

        # mock up a regular event to pass into _process_pulled_event
        pulled_event = make_event_from_dict(
            self.add_hashes_and_signatures(
                {
                    "type": "test_regular_type",
                    "room_id": room_id,
                    "sender": OTHER_USER,
                    "prev_events": [prev_event.event_id],
                    "auth_events": auth_event_ids,
                    "origin_server_ts": 1,
                    "depth": 12,
                    "content": {"body": "pulled"},
                }
            ),
            room_version,
        )

        # we expect an outbound request to /state_ids, so stub that out
        self.mock_federation_transport_client.get_room_state_ids.return_value = (
            make_awaitable(
                {
                    "pdu_ids": [e.event_id for e in state_at_prev_event],
                    "auth_chain_ids": [],
                }
            )
        )

        # we also expect an outbound request to /state
        self.mock_federation_transport_client.get_room_state.return_value = (
            make_awaitable(
                StateRequestResponse(auth_events=[], state=state_at_prev_event)
            )
        )

        # we have to bump the clock a bit, to keep the retry logic in
        # FederationClient.get_pdu happy
        self.reactor.advance(60000)

        # Finally, the call under test: send the pulled event into _process_pulled_event
        with LoggingContext("test"):
            self.get_success(
                self.hs.get_federation_event_handler()._process_pulled_event(
                    self.OTHER_SERVER_NAME, pulled_event, backfilled=False
                )
            )

        # check that the event is correctly persisted
        persisted = self.get_success(main_store.get_event(pulled_event.event_id))
        self.assertIsNotNone(persisted, "pulled event was not persisted at all")
        self.assertFalse(
            persisted.internal_metadata.is_outlier(), "pulled event was an outlier"
        )

        # check that the state at that event is as expected
        state = self.get_success(
            state_storage_controller.get_state_ids_for_event(pulled_event.event_id)
        )
        expected_state = {
            (e.type, e.state_key): e.event_id for e in state_at_prev_event
        }
        self.assertEqual(state, expected_state)

        if prev_exists_as_outlier:
            self.mock_federation_transport_client.get_event.assert_not_called()
