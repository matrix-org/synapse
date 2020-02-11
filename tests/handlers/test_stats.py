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

from mock import Mock

from twisted.internet import defer

from synapse.api.constants import EventTypes, Membership
from synapse.rest import admin
from synapse.rest.client.v1 import login, room

from tests import unittest


class StatsRoomTests(unittest.HomeserverTestCase):

    servlets = [
        admin.register_servlets_for_client_rest_resource,
        room.register_servlets,
        login.register_servlets,
    ]

    def prepare(self, reactor, clock, hs):

        self.store = hs.get_datastore()
        self.handler = self.hs.get_stats_handler()

    def _add_background_updates(self):
        """
        Add the background updates we need to run.
        """
        # Ugh, have to reset this flag
        self.store._all_done = False

        self.get_success(
            self.store._simple_insert(
                "background_updates",
                {"update_name": "populate_stats_createtables", "progress_json": "{}"},
            )
        )
        self.get_success(
            self.store._simple_insert(
                "background_updates",
                {
                    "update_name": "populate_stats_process_rooms",
                    "progress_json": "{}",
                    "depends_on": "populate_stats_createtables",
                },
            )
        )
        self.get_success(
            self.store._simple_insert(
                "background_updates",
                {
                    "update_name": "populate_stats_cleanup",
                    "progress_json": "{}",
                    "depends_on": "populate_stats_process_rooms",
                },
            )
        )

    def test_initial_room(self):
        """
        The background updates will build the table from scratch.
        """
        r = self.get_success(self.store.get_all_room_state())
        self.assertEqual(len(r), 0)

        # Disable stats
        self.hs.config.stats_enabled = False
        self.handler.stats_enabled = False

        u1 = self.register_user("u1", "pass")
        u1_token = self.login("u1", "pass")

        room_1 = self.helper.create_room_as(u1, tok=u1_token)
        self.helper.send_state(
            room_1, event_type="m.room.topic", body={"topic": "foo"}, tok=u1_token
        )

        # Stats disabled, shouldn't have done anything
        r = self.get_success(self.store.get_all_room_state())
        self.assertEqual(len(r), 0)

        # Enable stats
        self.hs.config.stats_enabled = True
        self.handler.stats_enabled = True

        # Do the initial population of the user directory via the background update
        self._add_background_updates()

        while not self.get_success(self.store.has_completed_background_updates()):
            self.get_success(self.store.do_next_background_update(100), by=0.1)

        r = self.get_success(self.store.get_all_room_state())

        self.assertEqual(len(r), 1)
        self.assertEqual(r[0]["topic"], "foo")

    def test_initial_earliest_token(self):
        """
        Ingestion via notify_new_event will ignore tokens that the background
        update have already processed.
        """
        self.reactor.advance(86401)

        self.hs.config.stats_enabled = False
        self.handler.stats_enabled = False

        u1 = self.register_user("u1", "pass")
        u1_token = self.login("u1", "pass")

        u2 = self.register_user("u2", "pass")
        u2_token = self.login("u2", "pass")

        u3 = self.register_user("u3", "pass")
        u3_token = self.login("u3", "pass")

        room_1 = self.helper.create_room_as(u1, tok=u1_token)
        self.helper.send_state(
            room_1, event_type="m.room.topic", body={"topic": "foo"}, tok=u1_token
        )

        # Begin the ingestion by creating the temp tables. This will also store
        # the position that the deltas should begin at, once they take over.
        self.hs.config.stats_enabled = True
        self.handler.stats_enabled = True
        self.store._all_done = False
        self.get_success(self.store.update_stats_stream_pos(None))

        self.get_success(
            self.store._simple_insert(
                "background_updates",
                {"update_name": "populate_stats_createtables", "progress_json": "{}"},
            )
        )

        while not self.get_success(self.store.has_completed_background_updates()):
            self.get_success(self.store.do_next_background_update(100), by=0.1)

        # Now, before the table is actually ingested, add some more events.
        self.helper.invite(room=room_1, src=u1, targ=u2, tok=u1_token)
        self.helper.join(room=room_1, user=u2, tok=u2_token)

        # Now do the initial ingestion.
        self.get_success(
            self.store._simple_insert(
                "background_updates",
                {"update_name": "populate_stats_process_rooms", "progress_json": "{}"},
            )
        )
        self.get_success(
            self.store._simple_insert(
                "background_updates",
                {
                    "update_name": "populate_stats_cleanup",
                    "progress_json": "{}",
                    "depends_on": "populate_stats_process_rooms",
                },
            )
        )

        self.store._all_done = False
        while not self.get_success(self.store.has_completed_background_updates()):
            self.get_success(self.store.do_next_background_update(100), by=0.1)

        self.reactor.advance(86401)

        # Now add some more events, triggering ingestion. Because of the stream
        # position being set to before the events sent in the middle, a simpler
        # implementation would reprocess those events, and say there were four
        # users, not three.
        self.helper.invite(room=room_1, src=u1, targ=u3, tok=u1_token)
        self.helper.join(room=room_1, user=u3, tok=u3_token)

        # Get the deltas! There should be two -- day 1, and day 2.
        r = self.get_success(self.store.get_deltas_for_room(room_1, 0))

        # The oldest has 2 joined members
        self.assertEqual(r[-1]["joined_members"], 2)

        # The newest has 3
        self.assertEqual(r[0]["joined_members"], 3)

    def test_incorrect_state_transition(self):
        """
        If the state transition is not one of (JOIN, INVITE, LEAVE, BAN) to
        (JOIN, INVITE, LEAVE, BAN), an error is raised.
        """
        events = {
            "a1": {"membership": Membership.LEAVE},
            "a2": {"membership": "not a real thing"},
        }

        def get_event(event_id, allow_none=True):
            m = Mock()
            m.content = events[event_id]
            d = defer.Deferred()
            self.reactor.callLater(0.0, d.callback, m)
            return d

        def get_received_ts(event_id):
            return defer.succeed(1)

        self.store.get_received_ts = get_received_ts
        self.store.get_event = get_event

        deltas = [
            {
                "type": EventTypes.Member,
                "state_key": "some_user",
                "room_id": "room",
                "event_id": "a1",
                "prev_event_id": "a2",
                "stream_id": 60,
            }
        ]

        f = self.get_failure(self.handler._handle_deltas(deltas), ValueError)
        self.assertEqual(
            f.value.args[0], "'not a real thing' is not a valid prev_membership"
        )

        # And the other way...
        deltas = [
            {
                "type": EventTypes.Member,
                "state_key": "some_user",
                "room_id": "room",
                "event_id": "a2",
                "prev_event_id": "a1",
                "stream_id": 100,
            }
        ]

        f = self.get_failure(self.handler._handle_deltas(deltas), ValueError)
        self.assertEqual(
            f.value.args[0], "'not a real thing' is not a valid membership"
        )

    def test_redacted_prev_event(self):
        """
        If the prev_event does not exist, then it is assumed to be a LEAVE.
        """
        u1 = self.register_user("u1", "pass")
        u1_token = self.login("u1", "pass")

        room_1 = self.helper.create_room_as(u1, tok=u1_token)

        # Do the initial population of the user directory via the background update
        self._add_background_updates()

        while not self.get_success(self.store.has_completed_background_updates()):
            self.get_success(self.store.do_next_background_update(100), by=0.1)

        events = {"a1": None, "a2": {"membership": Membership.JOIN}}

        def get_event(event_id, allow_none=True):
            if events.get(event_id):
                m = Mock()
                m.content = events[event_id]
            else:
                m = None
            d = defer.Deferred()
            self.reactor.callLater(0.0, d.callback, m)
            return d

        def get_received_ts(event_id):
            return defer.succeed(1)

        self.store.get_received_ts = get_received_ts
        self.store.get_event = get_event

        deltas = [
            {
                "type": EventTypes.Member,
                "state_key": "some_user:test",
                "room_id": room_1,
                "event_id": "a2",
                "prev_event_id": "a1",
                "stream_id": 100,
            }
        ]

        # Handle our fake deltas, which has a user going from LEAVE -> JOIN.
        self.get_success(self.handler._handle_deltas(deltas))

        # One delta, with two joined members -- the room creator, and our fake
        # user.
        r = self.get_success(self.store.get_deltas_for_room(room_1, 0))
        self.assertEqual(len(r), 1)
        self.assertEqual(r[0]["joined_members"], 2)
