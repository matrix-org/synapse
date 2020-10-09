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

from typing import List, Optional

from synapse.api.constants import EventTypes, Membership
from synapse.events import EventBase
from synapse.replication.tcp.commands import RdataCommand
from synapse.replication.tcp.streams._base import _STREAM_UPDATE_TARGET_ROW_COUNT
from synapse.replication.tcp.streams.events import (
    EventsStreamCurrentStateRow,
    EventsStreamEventRow,
    EventsStreamRow,
)
from synapse.rest import admin
from synapse.rest.client.v1 import login, room

from tests.replication._base import BaseStreamTestCase
from tests.test_utils.event_injection import inject_event, inject_member_event


class EventsStreamTestCase(BaseStreamTestCase):
    servlets = [
        admin.register_servlets,
        login.register_servlets,
        room.register_servlets,
    ]

    def prepare(self, reactor, clock, hs):
        super().prepare(reactor, clock, hs)
        self.user_id = self.register_user("u1", "pass")
        self.user_tok = self.login("u1", "pass")

        self.reconnect()

        self.room_id = self.helper.create_room_as(tok=self.user_tok)
        self.test_handler.received_rdata_rows.clear()

    def test_update_function_event_row_limit(self):
        """Test replication with many non-state events

        Checks that all events are correctly replicated when there are lots of
        event rows to be replicated.
        """
        # disconnect, so that we can stack up some changes
        self.disconnect()

        # generate lots of non-state events. We inject them using inject_event
        # so that they are not send out over replication until we call self.replicate().
        events = [
            self._inject_test_event()
            for _ in range(_STREAM_UPDATE_TARGET_ROW_COUNT + 1)
        ]

        # also one state event
        state_event = self._inject_state_event()

        # check we're testing what we think we are: no rows should yet have been
        # received
        self.assertEqual([], self.test_handler.received_rdata_rows)

        # now reconnect to pull the updates
        self.reconnect()
        self.replicate()

        # we should have received all the expected rows in the right order (as
        # well as various cache invalidation updates which we ignore)
        received_rows = [
            row for row in self.test_handler.received_rdata_rows if row[0] == "events"
        ]

        for event in events:
            stream_name, token, row = received_rows.pop(0)
            self.assertEqual("events", stream_name)
            self.assertIsInstance(row, EventsStreamRow)
            self.assertEqual(row.type, "ev")
            self.assertIsInstance(row.data, EventsStreamEventRow)
            self.assertEqual(row.data.event_id, event.event_id)

        stream_name, token, row = received_rows.pop(0)
        self.assertIsInstance(row, EventsStreamRow)
        self.assertIsInstance(row.data, EventsStreamEventRow)
        self.assertEqual(row.data.event_id, state_event.event_id)

        stream_name, token, row = received_rows.pop(0)
        self.assertEqual("events", stream_name)
        self.assertIsInstance(row, EventsStreamRow)
        self.assertEqual(row.type, "state")
        self.assertIsInstance(row.data, EventsStreamCurrentStateRow)
        self.assertEqual(row.data.event_id, state_event.event_id)

        self.assertEqual([], received_rows)

    def test_update_function_huge_state_change(self):
        """Test replication with many state events

        Ensures that all events are correctly replicated when there are lots of
        state change rows to be replicated.
        """

        # we want to generate lots of state changes at a single stream ID.
        #
        # We do this by having two branches in the DAG. On one, we have a moderator
        # which that generates lots of state; on the other, we de-op the moderator,
        # thus invalidating all the state.

        OTHER_USER = "@other_user:localhost"

        # have the user join
        self.get_success(
            inject_member_event(self.hs, self.room_id, OTHER_USER, Membership.JOIN)
        )

        # Update existing power levels with mod at PL50
        pls = self.helper.get_state(
            self.room_id, EventTypes.PowerLevels, tok=self.user_tok
        )
        pls["users"][OTHER_USER] = 50
        self.helper.send_state(
            self.room_id, EventTypes.PowerLevels, pls, tok=self.user_tok,
        )

        # this is the point in the DAG where we make a fork
        fork_point = self.get_success(
            self.hs.get_datastore().get_latest_event_ids_in_room(self.room_id)
        )  # type: List[str]

        events = [
            self._inject_state_event(sender=OTHER_USER)
            for _ in range(_STREAM_UPDATE_TARGET_ROW_COUNT)
        ]

        self.replicate()
        # all those events and state changes should have landed
        self.assertGreaterEqual(
            len(self.test_handler.received_rdata_rows), 2 * len(events)
        )

        # disconnect, so that we can stack up the changes
        self.disconnect()
        self.test_handler.received_rdata_rows.clear()

        # a state event which doesn't get rolled back, to check that the state
        # before the huge update comes through ok
        state1 = self._inject_state_event()

        # roll back all the state by de-modding the user
        prev_events = fork_point
        pls["users"][OTHER_USER] = 0
        pl_event = self.get_success(
            inject_event(
                self.hs,
                prev_event_ids=prev_events,
                type=EventTypes.PowerLevels,
                state_key="",
                sender=self.user_id,
                room_id=self.room_id,
                content=pls,
            )
        )

        # one more bit of state that doesn't get rolled back
        state2 = self._inject_state_event()

        # check we're testing what we think we are: no rows should yet have been
        # received
        self.assertEqual([], self.test_handler.received_rdata_rows)

        # now reconnect to pull the updates
        self.reconnect()
        self.replicate()

        # we should have received all the expected rows in the right order (as
        # well as various cache invalidation updates which we ignore)
        #
        # we expect:
        #
        # - two rows for state1
        # - the PL event row, plus state rows for the PL event and each
        #       of the states that got reverted.
        # - two rows for state2

        received_rows = [
            row for row in self.test_handler.received_rdata_rows if row[0] == "events"
        ]

        # first check the first two rows, which should be state1

        stream_name, token, row = received_rows.pop(0)
        self.assertEqual("events", stream_name)
        self.assertIsInstance(row, EventsStreamRow)
        self.assertEqual(row.type, "ev")
        self.assertIsInstance(row.data, EventsStreamEventRow)
        self.assertEqual(row.data.event_id, state1.event_id)

        stream_name, token, row = received_rows.pop(0)
        self.assertIsInstance(row, EventsStreamRow)
        self.assertEqual(row.type, "state")
        self.assertIsInstance(row.data, EventsStreamCurrentStateRow)
        self.assertEqual(row.data.event_id, state1.event_id)

        # now the last two rows, which should be state2
        stream_name, token, row = received_rows.pop(-2)
        self.assertEqual("events", stream_name)
        self.assertIsInstance(row, EventsStreamRow)
        self.assertEqual(row.type, "ev")
        self.assertIsInstance(row.data, EventsStreamEventRow)
        self.assertEqual(row.data.event_id, state2.event_id)

        stream_name, token, row = received_rows.pop(-1)
        self.assertIsInstance(row, EventsStreamRow)
        self.assertEqual(row.type, "state")
        self.assertIsInstance(row.data, EventsStreamCurrentStateRow)
        self.assertEqual(row.data.event_id, state2.event_id)

        # that should leave us with the rows for the PL event
        self.assertEqual(len(received_rows), len(events) + 2)

        stream_name, token, row = received_rows.pop(0)
        self.assertEqual("events", stream_name)
        self.assertIsInstance(row, EventsStreamRow)
        self.assertEqual(row.type, "ev")
        self.assertIsInstance(row.data, EventsStreamEventRow)
        self.assertEqual(row.data.event_id, pl_event.event_id)

        # the state rows are unsorted
        state_rows = []  # type: List[EventsStreamCurrentStateRow]
        for stream_name, token, row in received_rows:
            self.assertEqual("events", stream_name)
            self.assertIsInstance(row, EventsStreamRow)
            self.assertEqual(row.type, "state")
            self.assertIsInstance(row.data, EventsStreamCurrentStateRow)
            state_rows.append(row.data)

        state_rows.sort(key=lambda r: r.state_key)

        sr = state_rows.pop(0)
        self.assertEqual(sr.type, EventTypes.PowerLevels)
        self.assertEqual(sr.event_id, pl_event.event_id)
        for sr in state_rows:
            self.assertEqual(sr.type, "test_state_event")
            # "None" indicates the state has been deleted
            self.assertIsNone(sr.event_id)

    def test_update_function_state_row_limit(self):
        """Test replication with many state events over several stream ids.
        """

        # we want to generate lots of state changes, but for this test, we want to
        # spread out the state changes over a few stream IDs.
        #
        # We do this by having two branches in the DAG. On one, we have four moderators,
        # each of which that generates lots of state; on the other, we de-op the users,
        # thus invalidating all the state.

        NUM_USERS = 4
        STATES_PER_USER = _STREAM_UPDATE_TARGET_ROW_COUNT // 4 + 1

        user_ids = ["@user%i:localhost" % (i,) for i in range(NUM_USERS)]

        # have the users join
        for u in user_ids:
            self.get_success(
                inject_member_event(self.hs, self.room_id, u, Membership.JOIN)
            )

        # Update existing power levels with mod at PL50
        pls = self.helper.get_state(
            self.room_id, EventTypes.PowerLevels, tok=self.user_tok
        )
        pls["users"].update({u: 50 for u in user_ids})
        self.helper.send_state(
            self.room_id, EventTypes.PowerLevels, pls, tok=self.user_tok,
        )

        # this is the point in the DAG where we make a fork
        fork_point = self.get_success(
            self.hs.get_datastore().get_latest_event_ids_in_room(self.room_id)
        )  # type: List[str]

        events = []  # type: List[EventBase]
        for user in user_ids:
            events.extend(
                self._inject_state_event(sender=user) for _ in range(STATES_PER_USER)
            )

        self.replicate()

        # all those events and state changes should have landed
        self.assertGreaterEqual(
            len(self.test_handler.received_rdata_rows), 2 * len(events)
        )

        # disconnect, so that we can stack up the changes
        self.disconnect()
        self.test_handler.received_rdata_rows.clear()

        # now roll back all that state by de-modding the users
        prev_events = fork_point
        pl_events = []
        for u in user_ids:
            pls["users"][u] = 0
            e = self.get_success(
                inject_event(
                    self.hs,
                    prev_event_ids=prev_events,
                    type=EventTypes.PowerLevels,
                    state_key="",
                    sender=self.user_id,
                    room_id=self.room_id,
                    content=pls,
                )
            )
            prev_events = [e.event_id]
            pl_events.append(e)

        # check we're testing what we think we are: no rows should yet have been
        # received
        self.assertEqual([], self.test_handler.received_rdata_rows)

        # now reconnect to pull the updates
        self.reconnect()
        self.replicate()

        # we should have received all the expected rows in the right order (as
        # well as various cache invalidation updates which we ignore)
        received_rows = [
            row for row in self.test_handler.received_rdata_rows if row[0] == "events"
        ]
        self.assertGreaterEqual(len(received_rows), len(events))
        for i in range(NUM_USERS):
            # for each user, we expect the PL event row, followed by state rows for
            # the PL event and each of the states that got reverted.
            stream_name, token, row = received_rows.pop(0)
            self.assertEqual("events", stream_name)
            self.assertIsInstance(row, EventsStreamRow)
            self.assertEqual(row.type, "ev")
            self.assertIsInstance(row.data, EventsStreamEventRow)
            self.assertEqual(row.data.event_id, pl_events[i].event_id)

            # the state rows are unsorted
            state_rows = []  # type: List[EventsStreamCurrentStateRow]
            for j in range(STATES_PER_USER + 1):
                stream_name, token, row = received_rows.pop(0)
                self.assertEqual("events", stream_name)
                self.assertIsInstance(row, EventsStreamRow)
                self.assertEqual(row.type, "state")
                self.assertIsInstance(row.data, EventsStreamCurrentStateRow)
                state_rows.append(row.data)

            state_rows.sort(key=lambda r: r.state_key)

            sr = state_rows.pop(0)
            self.assertEqual(sr.type, EventTypes.PowerLevels)
            self.assertEqual(sr.event_id, pl_events[i].event_id)
            for sr in state_rows:
                self.assertEqual(sr.type, "test_state_event")
                # "None" indicates the state has been deleted
                self.assertIsNone(sr.event_id)

        self.assertEqual([], received_rows)

    def test_backwards_stream_id(self):
        """
        Test that RDATA that comes after the current position should be discarded.
        """
        # disconnect, so that we can stack up some changes
        self.disconnect()

        # Generate an events. We inject them using inject_event so that they are
        # not send out over replication until we call self.replicate().
        event = self._inject_test_event()

        # check we're testing what we think we are: no rows should yet have been
        # received
        self.assertEqual([], self.test_handler.received_rdata_rows)

        # now reconnect to pull the updates
        self.reconnect()
        self.replicate()

        # We should have received the expected single row (as well as various
        # cache invalidation updates which we ignore).
        received_rows = [
            row for row in self.test_handler.received_rdata_rows if row[0] == "events"
        ]

        # There should be a single received row.
        self.assertEqual(len(received_rows), 1)

        stream_name, token, row = received_rows[0]
        self.assertEqual("events", stream_name)
        self.assertIsInstance(row, EventsStreamRow)
        self.assertEqual(row.type, "ev")
        self.assertIsInstance(row.data, EventsStreamEventRow)
        self.assertEqual(row.data.event_id, event.event_id)

        # Reset the data.
        self.test_handler.received_rdata_rows = []

        # Save the current token for later.
        worker_events_stream = self.worker_hs.get_replication_streams()["events"]
        prev_token = worker_events_stream.current_token("master")

        # Manually send an old RDATA command, which should get dropped. This
        # re-uses the row from above, but with an earlier stream token.
        self.hs.get_tcp_replication().send_command(
            RdataCommand("events", "master", 1, row)
        )

        # No updates have been received (because it was discard as old).
        received_rows = [
            row for row in self.test_handler.received_rdata_rows if row[0] == "events"
        ]
        self.assertEqual(len(received_rows), 0)

        # Ensure the stream has not gone backwards.
        current_token = worker_events_stream.current_token("master")
        self.assertGreaterEqual(current_token, prev_token)

    event_count = 0

    def _inject_test_event(
        self, body: Optional[str] = None, sender: Optional[str] = None, **kwargs
    ) -> EventBase:
        if sender is None:
            sender = self.user_id

        if body is None:
            body = "event %i" % (self.event_count,)
            self.event_count += 1

        return self.get_success(
            inject_event(
                self.hs,
                room_id=self.room_id,
                sender=sender,
                type="test_event",
                content={"body": body},
                **kwargs
            )
        )

    def _inject_state_event(
        self,
        body: Optional[str] = None,
        state_key: Optional[str] = None,
        sender: Optional[str] = None,
    ) -> EventBase:
        if sender is None:
            sender = self.user_id

        if state_key is None:
            state_key = "state_%i" % (self.event_count,)
            self.event_count += 1

        if body is None:
            body = "state event %s" % (state_key,)

        return self.get_success(
            inject_event(
                self.hs,
                room_id=self.room_id,
                sender=sender,
                type="test_state_event",
                state_key=state_key,
                content={"body": body},
            )
        )
