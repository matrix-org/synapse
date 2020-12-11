# -*- coding: utf-8 -*-
# Copyright 2020 The Matrix.org Foundation C.I.C.
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


from synapse.api.constants import EventTypes, Membership
from synapse.api.room_versions import RoomVersions
from synapse.federation.federation_base import event_from_pdu_json
from synapse.rest import admin
from synapse.rest.client.v1 import login, room

from tests.unittest import HomeserverTestCase


class ExtremPruneTestCase(HomeserverTestCase):
    servlets = [
        admin.register_servlets,
        room.register_servlets,
        login.register_servlets,
    ]

    def test_prune_gap(self):
        """Test that we drop extremities after a gap when we see an event from
        the same domain.
        """

        state = self.hs.get_state_handler()
        persistence = self.hs.get_storage().persistence
        store = self.hs.get_datastore()

        self.register_user("user", "pass")
        token = self.login("user", "pass")
        room_id = self.helper.create_room_as(
            "user", room_version=RoomVersions.V6.identifier, tok=token
        )

        body = self.helper.send(room_id, body="Test", tok=token)
        local_message_event_id = body["event_id"]

        # Fudge a remote event an persist it. This will be the extremity before
        # the gap.
        remote_event_1 = event_from_pdu_json(
            {
                "type": EventTypes.Message,
                "content": {},
                "room_id": room_id,
                "sender": "@user:other",
                "depth": 5,
                "prev_events": [local_message_event_id],
                "auth_events": [],
                "origin_server_ts": self.clock.time_msec(),
            },
            RoomVersions.V6,
        )

        context = self.get_success(state.compute_event_context(remote_event_1))
        self.get_success(persistence.persist_event(remote_event_1, context))

        # Check that the current extremities is the remote event.
        extremities = self.get_success(store.get_prev_events_for_room(room_id))
        self.assertCountEqual(extremities, [remote_event_1.event_id])

        # Fudge a second event which points to an event we don't have. This is a
        # state event so that the state changes (otherwise we won't prune the
        # extremity as they'll have the same state group).
        remote_event_2 = event_from_pdu_json(
            {
                "type": EventTypes.Member,
                "state_key": "@user:other",
                "content": {"membership": Membership.JOIN},
                "room_id": room_id,
                "sender": "@user:other",
                "depth": 10,
                "prev_events": ["$some_unknown_message"],
                "auth_events": [],
                "origin_server_ts": self.clock.time_msec(),
            },
            RoomVersions.V6,
        )

        state_before_gap = self.get_success(state.get_current_state(room_id))

        context = self.get_success(
            state.compute_event_context(
                remote_event_2, old_state=state_before_gap.values()
            )
        )

        self.get_success(persistence.persist_event(remote_event_2, context))

        # Check the new extremity is just the new remote event.
        extremities = self.get_success(store.get_prev_events_for_room(room_id))
        self.assertCountEqual(extremities, [remote_event_2.event_id])

    def test_dont_prune_gap_if_state_different(self):
        """Test that we don't prune extremities after a gap if the resolved
        state is different.
        """

        state = self.hs.get_state_handler()
        persistence = self.hs.get_storage().persistence
        store = self.hs.get_datastore()

        self.register_user("user", "pass")
        token = self.login("user", "pass")
        room_id = self.helper.create_room_as(
            "user", room_version=RoomVersions.V6.identifier, tok=token
        )

        body = self.helper.send(room_id, body="Test", tok=token)
        local_message_event_id = body["event_id"]

        # Fudge a remote event an persist it. This will be the extremity before
        # the gap.
        remote_event_1 = event_from_pdu_json(
            {
                "type": EventTypes.Message,
                "state_key": "@user:other",
                "content": {},
                "room_id": room_id,
                "sender": "@user:other",
                "depth": 5,
                "prev_events": [local_message_event_id],
                "auth_events": [],
                "origin_server_ts": self.clock.time_msec(),
            },
            RoomVersions.V6,
        )

        context = self.get_success(state.compute_event_context(remote_event_1))
        self.get_success(persistence.persist_event(remote_event_1, context))

        # Check that the current extremities is the remote event.
        extremities = self.get_success(store.get_prev_events_for_room(room_id))
        self.assertCountEqual(extremities, [remote_event_1.event_id])

        # Fudge a second event which points to an event we don't have.
        remote_event_2 = event_from_pdu_json(
            {
                "type": EventTypes.Message,
                "state_key": "@user:other",
                "content": {},
                "room_id": room_id,
                "sender": "@user:other",
                "depth": 10,
                "prev_events": ["$some_unknown_message"],
                "auth_events": [],
                "origin_server_ts": self.clock.time_msec(),
            },
            RoomVersions.V6,
        )

        # Now we persist it with state with a dropped history visibility
        # setting. The state resolution across the old and new event will then
        # include it, and so the resolved state won't match the new state.
        state_before_gap = dict(self.get_success(state.get_current_state(room_id)))
        state_before_gap.pop(("m.room.history_visibility", ""))

        context = self.get_success(
            state.compute_event_context(
                remote_event_2, old_state=state_before_gap.values()
            )
        )

        self.get_success(persistence.persist_event(remote_event_2, context))

        # Check that we haven't dropped the old extremity.
        extremities = self.get_success(store.get_prev_events_for_room(room_id))
        self.assertCountEqual(
            extremities, [remote_event_1.event_id, remote_event_2.event_id]
        )
