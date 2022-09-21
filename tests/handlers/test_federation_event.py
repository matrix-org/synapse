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
from typing import Optional
from unittest import mock

from synapse.api.errors import AuthError
from synapse.api.room_versions import RoomVersion
from synapse.event_auth import (
    check_state_dependent_auth_rules,
    check_state_independent_auth_rules,
)
from synapse.events import make_event_from_dict
from synapse.events.snapshot import EventContext
from synapse.federation.transport.client import StateRequestResponse
from synapse.logging.context import LoggingContext
from synapse.rest import admin
from synapse.rest.client import login, room
from synapse.state.v2 import _mainline_sort, _reverse_topological_power_sort
from synapse.types import JsonDict

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
                self.add_hashes_and_signatures_from_other_server(
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
            self.add_hashes_and_signatures_from_other_server(
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
            self.add_hashes_and_signatures_from_other_server(
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

    def test_process_pulled_event_records_failed_backfill_attempts(
        self,
    ) -> None:
        """
        Test to make sure that failed backfill attempts for an event are
        recorded in the `event_failed_pull_attempts` table.

        In this test, we pretend we are processing a "pulled" event via
        backfill. The pulled event has a fake `prev_event` which our server has
        obviously never seen before so it attempts to request the state at that
        `prev_event` which expectedly fails because it's a fake event. Because
        the server can't fetch the state at the missing `prev_event`, the
        "pulled" event fails the history check and is fails to process.

        We check that we correctly record the number of failed pull attempts
        of the pulled event and as a sanity check, that the "pulled" event isn't
        persisted.
        """
        OTHER_USER = f"@user:{self.OTHER_SERVER_NAME}"
        main_store = self.hs.get_datastores().main

        # Create the room
        user_id = self.register_user("kermit", "test")
        tok = self.login("kermit", "test")
        room_id = self.helper.create_room_as(room_creator=user_id, tok=tok)
        room_version = self.get_success(main_store.get_room_version(room_id))

        # We expect an outbound request to /state_ids, so stub that out
        self.mock_federation_transport_client.get_room_state_ids.return_value = make_awaitable(
            {
                # Mimic the other server not knowing about the state at all.
                # We want to cause Synapse to throw an error (`Unable to get
                # missing prev_event $fake_prev_event`) and fail to backfill
                # the pulled event.
                "pdu_ids": [],
                "auth_chain_ids": [],
            }
        )
        # We also expect an outbound request to /state
        self.mock_federation_transport_client.get_room_state.return_value = make_awaitable(
            StateRequestResponse(
                # Mimic the other server not knowing about the state at all.
                # We want to cause Synapse to throw an error (`Unable to get
                # missing prev_event $fake_prev_event`) and fail to backfill
                # the pulled event.
                auth_events=[],
                state=[],
            )
        )

        pulled_event = make_event_from_dict(
            self.add_hashes_and_signatures_from_other_server(
                {
                    "type": "test_regular_type",
                    "room_id": room_id,
                    "sender": OTHER_USER,
                    "prev_events": [
                        # The fake prev event will make the pulled event fail
                        # the history check (`Unable to get missing prev_event
                        # $fake_prev_event`)
                        "$fake_prev_event"
                    ],
                    "auth_events": [],
                    "origin_server_ts": 1,
                    "depth": 12,
                    "content": {"body": "pulled"},
                }
            ),
            room_version,
        )

        # The function under test: try to process the pulled event
        with LoggingContext("test"):
            self.get_success(
                self.hs.get_federation_event_handler()._process_pulled_event(
                    self.OTHER_SERVER_NAME, pulled_event, backfilled=True
                )
            )

        # Make sure our failed pull attempt was recorded
        backfill_num_attempts = self.get_success(
            main_store.db_pool.simple_select_one_onecol(
                table="event_failed_pull_attempts",
                keyvalues={"event_id": pulled_event.event_id},
                retcol="num_attempts",
            )
        )
        self.assertEqual(backfill_num_attempts, 1)

        # The function under test: try to process the pulled event again
        with LoggingContext("test"):
            self.get_success(
                self.hs.get_federation_event_handler()._process_pulled_event(
                    self.OTHER_SERVER_NAME, pulled_event, backfilled=True
                )
            )

        # Make sure our second failed pull attempt was recorded (`num_attempts` was incremented)
        backfill_num_attempts = self.get_success(
            main_store.db_pool.simple_select_one_onecol(
                table="event_failed_pull_attempts",
                keyvalues={"event_id": pulled_event.event_id},
                retcol="num_attempts",
            )
        )
        self.assertEqual(backfill_num_attempts, 2)

        # And as a sanity check, make sure the event was not persisted through all of this.
        persisted = self.get_success(
            main_store.get_event(pulled_event.event_id, allow_none=True)
        )
        self.assertIsNone(
            persisted,
            "pulled event that fails the history check should not be persisted at all",
        )

    def test_process_pulled_event_clears_backfill_attempts_after_being_successfully_persisted(
        self,
    ) -> None:
        """
        Test to make sure that failed pull attempts
        (`event_failed_pull_attempts` table) for an event are cleared after the
        event is successfully persisted.

        In this test, we pretend we are processing a "pulled" event via
        backfill. The pulled event succesfully processes and the backward
        extremeties are updated along with clearing out any failed pull attempts
        for those old extremities.

        We check that we correctly cleared failed pull attempts of the
        pulled event.
        """
        OTHER_USER = f"@user:{self.OTHER_SERVER_NAME}"
        main_store = self.hs.get_datastores().main

        # Create the room
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

        pulled_event = make_event_from_dict(
            self.add_hashes_and_signatures_from_other_server(
                {
                    "type": "test_regular_type",
                    "room_id": room_id,
                    "sender": OTHER_USER,
                    "prev_events": [member_event.event_id],
                    "auth_events": auth_event_ids,
                    "origin_server_ts": 1,
                    "depth": 12,
                    "content": {"body": "pulled"},
                }
            ),
            room_version,
        )

        # Fake the "pulled" event failing to backfill once so we can test
        # if it's cleared out later on.
        self.get_success(
            main_store.record_event_failed_pull_attempt(
                pulled_event.room_id, pulled_event.event_id, "fake cause"
            )
        )
        # Make sure we have a failed pull attempt recorded for the pulled event
        backfill_num_attempts = self.get_success(
            main_store.db_pool.simple_select_one_onecol(
                table="event_failed_pull_attempts",
                keyvalues={"event_id": pulled_event.event_id},
                retcol="num_attempts",
            )
        )
        self.assertEqual(backfill_num_attempts, 1)

        # The function under test: try to process the pulled event
        with LoggingContext("test"):
            self.get_success(
                self.hs.get_federation_event_handler()._process_pulled_event(
                    self.OTHER_SERVER_NAME, pulled_event, backfilled=True
                )
            )

        # Make sure the failed pull attempts for the pulled event are cleared
        backfill_num_attempts = self.get_success(
            main_store.db_pool.simple_select_one_onecol(
                table="event_failed_pull_attempts",
                keyvalues={"event_id": pulled_event.event_id},
                retcol="num_attempts",
                allow_none=True,
            )
        )
        self.assertIsNone(backfill_num_attempts)

        # And as a sanity check, make sure the "pulled" event was persisted.
        persisted = self.get_success(
            main_store.get_event(pulled_event.event_id, allow_none=True)
        )
        self.assertIsNotNone(persisted, "pulled event was not persisted at all")

    def test_process_pulled_event_with_rejected_missing_state(self) -> None:
        """Ensure that we correctly handle pulled events with missing state containing a
        rejected state event

        In this test, we pretend we are processing a "pulled" event (eg, via backfill
        or get_missing_events). The pulled event has a prev_event we haven't previously
        seen, so the server requests the state at that prev_event. We expect the server
        to make a /state request.

        We simulate a remote server whose /state includes a rejected kick event for a
        local user. Notably, the kick event is rejected only because it cites a rejected
        auth event and would otherwise be accepted based on the room state. During state
        resolution, we re-run auth and can potentially introduce such rejected events
        into the state if we are not careful.

        We check that the pulled event is correctly persisted, and that the state
        afterwards does not include the rejected kick.
        """
        # The DAG we are testing looks like:
        #
        #                 ...
        #                  |
        #                  v
        #       remote admin user joins
        #                |   |
        #        +-------+   +-------+
        #        |                   |
        #        |          rejected power levels
        #        |           from remote server
        #        |                   |
        #        |                   v
        #        |       rejected kick of local user
        #        v           from remote server
        # new power levels           |
        #        |                   v
        #        |             missing event
        #        |           from remote server
        #        |                   |
        #        +-------+   +-------+
        #                |   |
        #                v   v
        #             pulled event
        #          from remote server
        #
        # (arrows are in the opposite direction to prev_events.)

        OTHER_USER = f"@user:{self.OTHER_SERVER_NAME}"
        main_store = self.hs.get_datastores().main

        # Create the room.
        kermit_user_id = self.register_user("kermit", "test")
        kermit_tok = self.login("kermit", "test")
        room_id = self.helper.create_room_as(
            room_creator=kermit_user_id, tok=kermit_tok
        )
        room_version = self.get_success(main_store.get_room_version(room_id))

        # Add another local user to the room. This user is going to be kicked in a
        # rejected event.
        bert_user_id = self.register_user("bert", "test")
        bert_tok = self.login("bert", "test")
        self.helper.join(room_id, user=bert_user_id, tok=bert_tok)

        # Allow the remote user to kick bert.
        # The remote user is going to send a rejected power levels event later on and we
        # need state resolution to order it before another power levels event kermit is
        # going to send later on. Hence we give both users the same power level, so that
        # ties are broken by `origin_server_ts`.
        self.helper.send_state(
            room_id,
            "m.room.power_levels",
            {"users": {kermit_user_id: 100, OTHER_USER: 100}},
            tok=kermit_tok,
        )

        # Add the remote user to the room.
        other_member_event = self.get_success(
            event_injection.inject_member_event(self.hs, room_id, OTHER_USER, "join")
        )

        initial_state_map = self.get_success(
            main_store.get_partial_current_state_ids(room_id)
        )
        create_event = self.get_success(
            main_store.get_event(initial_state_map[("m.room.create", "")])
        )
        bert_member_event = self.get_success(
            main_store.get_event(initial_state_map[("m.room.member", bert_user_id)])
        )
        power_levels_event = self.get_success(
            main_store.get_event(initial_state_map[("m.room.power_levels", "")])
        )

        # We now need a rejected state event that will fail
        # `check_state_independent_auth_rules` but pass
        # `check_state_dependent_auth_rules`.

        # First, we create a power levels event that we pretend the remote server has
        # accepted, but the local homeserver will reject.
        next_depth = 100
        next_timestamp = other_member_event.origin_server_ts + 100
        rejected_power_levels_event = make_event_from_dict(
            self.add_hashes_and_signatures_from_other_server(
                {
                    "type": "m.room.power_levels",
                    "state_key": "",
                    "room_id": room_id,
                    "sender": OTHER_USER,
                    "prev_events": [other_member_event.event_id],
                    "auth_events": [
                        initial_state_map[("m.room.create", "")],
                        initial_state_map[("m.room.power_levels", "")],
                        # The event will be rejected because of the duplicated auth
                        # event.
                        other_member_event.event_id,
                        other_member_event.event_id,
                    ],
                    "origin_server_ts": next_timestamp,
                    "depth": next_depth,
                    "content": power_levels_event.content,
                }
            ),
            room_version,
        )
        next_depth += 1
        next_timestamp += 100

        with LoggingContext("send_rejected_power_levels_event"):
            self.get_success(
                self.hs.get_federation_event_handler()._process_pulled_event(
                    self.OTHER_SERVER_NAME,
                    rejected_power_levels_event,
                    backfilled=False,
                )
            )
            self.assertEqual(
                self.get_success(
                    main_store.get_rejection_reason(
                        rejected_power_levels_event.event_id
                    )
                ),
                "auth_error",
            )

        # Then we create a kick event for a local user that cites the rejected power
        # levels event in its auth events. The kick event will be rejected solely
        # because of the rejected auth event and would otherwise be accepted.
        rejected_kick_event = make_event_from_dict(
            self.add_hashes_and_signatures_from_other_server(
                {
                    "type": "m.room.member",
                    "state_key": bert_user_id,
                    "room_id": room_id,
                    "sender": OTHER_USER,
                    "prev_events": [rejected_power_levels_event.event_id],
                    "auth_events": [
                        initial_state_map[("m.room.create", "")],
                        rejected_power_levels_event.event_id,
                        initial_state_map[("m.room.member", bert_user_id)],
                        initial_state_map[("m.room.member", OTHER_USER)],
                    ],
                    "origin_server_ts": next_timestamp,
                    "depth": next_depth,
                    "content": {"membership": "leave"},
                }
            ),
            room_version,
        )
        next_depth += 1
        next_timestamp += 100

        # The kick event must fail the state-independent auth rules, but pass the
        # state-dependent auth rules, so that it has a chance of making it through state
        # resolution.
        self.get_failure(
            check_state_independent_auth_rules(main_store, rejected_kick_event),
            AuthError,
        )
        check_state_dependent_auth_rules(
            rejected_kick_event,
            [create_event, power_levels_event, other_member_event, bert_member_event],
        )

        # The kick event must also win over the original member event during state
        # resolution.
        self.assertEqual(
            self.get_success(
                _mainline_sort(
                    self.clock,
                    room_id,
                    event_ids=[
                        bert_member_event.event_id,
                        rejected_kick_event.event_id,
                    ],
                    resolved_power_event_id=power_levels_event.event_id,
                    event_map={
                        bert_member_event.event_id: bert_member_event,
                        rejected_kick_event.event_id: rejected_kick_event,
                    },
                    state_res_store=main_store,
                )
            ),
            [bert_member_event.event_id, rejected_kick_event.event_id],
            "The rejected kick event will not be applied after bert's join event "
            "during state resolution. The test setup is incorrect.",
        )

        with LoggingContext("send_rejected_kick_event"):
            self.get_success(
                self.hs.get_federation_event_handler()._process_pulled_event(
                    self.OTHER_SERVER_NAME, rejected_kick_event, backfilled=False
                )
            )
            self.assertEqual(
                self.get_success(
                    main_store.get_rejection_reason(rejected_kick_event.event_id)
                ),
                "auth_error",
            )

        # We need another power levels event which will win over the rejected one during
        # state resolution, otherwise we hit other issues where we end up with rejected
        # a power levels event during state resolution.
        self.reactor.advance(100)  # ensure the `origin_server_ts` is larger
        new_power_levels_event = self.get_success(
            main_store.get_event(
                self.helper.send_state(
                    room_id,
                    "m.room.power_levels",
                    {"users": {kermit_user_id: 100, OTHER_USER: 100, bert_user_id: 1}},
                    tok=kermit_tok,
                )["event_id"]
            )
        )
        self.assertEqual(
            self.get_success(
                _reverse_topological_power_sort(
                    self.clock,
                    room_id,
                    event_ids=[
                        new_power_levels_event.event_id,
                        rejected_power_levels_event.event_id,
                    ],
                    event_map={},
                    state_res_store=main_store,
                    full_conflicted_set=set(),
                )
            ),
            [rejected_power_levels_event.event_id, new_power_levels_event.event_id],
            "The power levels events will not have the desired ordering during state "
            "resolution. The test setup is incorrect.",
        )

        # Create a missing event, so that the local homeserver has to do a `/state` or
        # `/state_ids` request to pull state from the remote homeserver.
        missing_event = make_event_from_dict(
            self.add_hashes_and_signatures_from_other_server(
                {
                    "type": "m.room.message",
                    "room_id": room_id,
                    "sender": OTHER_USER,
                    "prev_events": [rejected_kick_event.event_id],
                    "auth_events": [
                        initial_state_map[("m.room.create", "")],
                        initial_state_map[("m.room.power_levels", "")],
                        initial_state_map[("m.room.member", OTHER_USER)],
                    ],
                    "origin_server_ts": next_timestamp,
                    "depth": next_depth,
                    "content": {"msgtype": "m.text", "body": "foo"},
                }
            ),
            room_version,
        )
        next_depth += 1
        next_timestamp += 100

        # The pulled event has two prev events, one of which is missing. We will make a
        # `/state` or `/state_ids` request to the remote homeserver to ask it for the
        # state before the missing prev event.
        pulled_event = make_event_from_dict(
            self.add_hashes_and_signatures_from_other_server(
                {
                    "type": "m.room.message",
                    "room_id": room_id,
                    "sender": OTHER_USER,
                    "prev_events": [
                        new_power_levels_event.event_id,
                        missing_event.event_id,
                    ],
                    "auth_events": [
                        initial_state_map[("m.room.create", "")],
                        new_power_levels_event.event_id,
                        initial_state_map[("m.room.member", OTHER_USER)],
                    ],
                    "origin_server_ts": next_timestamp,
                    "depth": next_depth,
                    "content": {"msgtype": "m.text", "body": "bar"},
                }
            ),
            room_version,
        )
        next_depth += 1
        next_timestamp += 100

        # Prepare the response for the `/state` or `/state_ids` request.
        # The remote server believes bert has been kicked, while the local server does
        # not.
        state_before_missing_event = self.get_success(
            main_store.get_events_as_list(initial_state_map.values())
        )
        state_before_missing_event = [
            event
            for event in state_before_missing_event
            if event.event_id != bert_member_event.event_id
        ]
        state_before_missing_event.append(rejected_kick_event)

        # We have to bump the clock a bit, to keep the retry logic in
        # `FederationClient.get_pdu` happy
        self.reactor.advance(60000)
        with LoggingContext("send_pulled_event"):

            async def get_event(
                destination: str, event_id: str, timeout: Optional[int] = None
            ) -> JsonDict:
                self.assertEqual(destination, self.OTHER_SERVER_NAME)
                self.assertEqual(event_id, missing_event.event_id)
                return {"pdus": [missing_event.get_pdu_json()]}

            async def get_room_state_ids(
                destination: str, room_id: str, event_id: str
            ) -> JsonDict:
                self.assertEqual(destination, self.OTHER_SERVER_NAME)
                self.assertEqual(event_id, missing_event.event_id)
                return {
                    "pdu_ids": [event.event_id for event in state_before_missing_event],
                    "auth_chain_ids": [],
                }

            async def get_room_state(
                room_version: RoomVersion, destination: str, room_id: str, event_id: str
            ) -> StateRequestResponse:
                self.assertEqual(destination, self.OTHER_SERVER_NAME)
                self.assertEqual(event_id, missing_event.event_id)
                return StateRequestResponse(
                    state=state_before_missing_event,
                    auth_events=[],
                )

            self.mock_federation_transport_client.get_event.side_effect = get_event
            self.mock_federation_transport_client.get_room_state_ids.side_effect = (
                get_room_state_ids
            )
            self.mock_federation_transport_client.get_room_state.side_effect = (
                get_room_state
            )

            self.get_success(
                self.hs.get_federation_event_handler()._process_pulled_event(
                    self.OTHER_SERVER_NAME, pulled_event, backfilled=False
                )
            )
            self.assertIsNone(
                self.get_success(
                    main_store.get_rejection_reason(pulled_event.event_id)
                ),
                "Pulled event was unexpectedly rejected, likely due to a problem with "
                "the test setup.",
            )
            self.assertEqual(
                {pulled_event.event_id},
                self.get_success(
                    main_store.have_events_in_timeline([pulled_event.event_id])
                ),
                "Pulled event was not persisted, likely due to a problem with the test "
                "setup.",
            )

            # We must not accept rejected events into the room state, so we expect bert
            # to not be kicked, even if the remote server believes so.
            new_state_map = self.get_success(
                main_store.get_partial_current_state_ids(room_id)
            )
            self.assertEqual(
                new_state_map[("m.room.member", bert_user_id)],
                bert_member_event.event_id,
                "Rejected kick event unexpectedly became part of room state.",
            )
