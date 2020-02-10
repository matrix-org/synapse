# -*- coding: utf-8 -*-
# Copyright 2019 The Matrix.org Foundation C.I.C.
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

import os.path

from synapse.storage import prepare_database
from synapse.types import Requester, UserID

from tests.unittest import HomeserverTestCase


class CleanupExtremBackgroundUpdateStoreTestCase(HomeserverTestCase):
    """
    Test the background update to clean forward extremities table.
    """

    def prepare(self, reactor, clock, homeserver):
        self.store = homeserver.get_datastore()
        self.room_creator = homeserver.get_room_creation_handler()

        # Create a test user and room
        self.user = UserID("alice", "test")
        self.requester = Requester(self.user, None, False, None, None)
        info = self.get_success(self.room_creator.create_room(self.requester, {}))
        self.room_id = info["room_id"]

    def run_background_update(self):
        """Re run the background update to clean up the extremities.
        """
        # Make sure we don't clash with in progress updates.
        self.assertTrue(self.store._all_done, "Background updates are still ongoing")

        schema_path = os.path.join(
            prepare_database.dir_path,
            "schema",
            "delta",
            "54",
            "delete_forward_extremities.sql",
        )

        def run_delta_file(txn):
            prepare_database.executescript(txn, schema_path)

        self.get_success(
            self.store.runInteraction("test_delete_forward_extremities", run_delta_file)
        )

        # Ugh, have to reset this flag
        self.store._all_done = False

        while not self.get_success(self.store.has_completed_background_updates()):
            self.get_success(self.store.do_next_background_update(100), by=0.1)

    def test_soft_failed_extremities_handled_correctly(self):
        """Test that extremities are correctly calculated in the presence of
        soft failed events.

        Tests a graph like:

            A <- SF1 <- SF2 <- B

        Where SF* are soft failed.
        """

        # Create the room graph
        event_id_1 = self.create_and_send_event(self.room_id, self.user)
        event_id_2 = self.create_and_send_event(
            self.room_id, self.user, True, [event_id_1]
        )
        event_id_3 = self.create_and_send_event(
            self.room_id, self.user, True, [event_id_2]
        )
        event_id_4 = self.create_and_send_event(
            self.room_id, self.user, False, [event_id_3]
        )

        # Check the latest events are as expected
        latest_event_ids = self.get_success(
            self.store.get_latest_event_ids_in_room(self.room_id)
        )

        self.assertEqual(latest_event_ids, [event_id_4])

    def test_basic_cleanup(self):
        """Test that extremities are correctly calculated in the presence of
        soft failed events.

        Tests a graph like:

            A <- SF1 <- B

        Where SF* are soft failed, and with extremities of A and B
        """
        # Create the room graph
        event_id_a = self.create_and_send_event(self.room_id, self.user)
        event_id_sf1 = self.create_and_send_event(
            self.room_id, self.user, True, [event_id_a]
        )
        event_id_b = self.create_and_send_event(
            self.room_id, self.user, False, [event_id_sf1]
        )

        # Add the new extremity and check the latest events are as expected
        self.add_extremity(self.room_id, event_id_a)

        latest_event_ids = self.get_success(
            self.store.get_latest_event_ids_in_room(self.room_id)
        )
        self.assertEqual(set(latest_event_ids), set((event_id_a, event_id_b)))

        # Run the background update and check it did the right thing
        self.run_background_update()

        latest_event_ids = self.get_success(
            self.store.get_latest_event_ids_in_room(self.room_id)
        )
        self.assertEqual(latest_event_ids, [event_id_b])

    def test_chain_of_fail_cleanup(self):
        """Test that extremities are correctly calculated in the presence of
        soft failed events.

        Tests a graph like:

            A <- SF1 <- SF2 <- B

        Where SF* are soft failed, and with extremities of A and B
        """
        # Create the room graph
        event_id_a = self.create_and_send_event(self.room_id, self.user)
        event_id_sf1 = self.create_and_send_event(
            self.room_id, self.user, True, [event_id_a]
        )
        event_id_sf2 = self.create_and_send_event(
            self.room_id, self.user, True, [event_id_sf1]
        )
        event_id_b = self.create_and_send_event(
            self.room_id, self.user, False, [event_id_sf2]
        )

        # Add the new extremity and check the latest events are as expected
        self.add_extremity(self.room_id, event_id_a)

        latest_event_ids = self.get_success(
            self.store.get_latest_event_ids_in_room(self.room_id)
        )
        self.assertEqual(set(latest_event_ids), set((event_id_a, event_id_b)))

        # Run the background update and check it did the right thing
        self.run_background_update()

        latest_event_ids = self.get_success(
            self.store.get_latest_event_ids_in_room(self.room_id)
        )
        self.assertEqual(latest_event_ids, [event_id_b])

    def test_forked_graph_cleanup(self):
        r"""Test that extremities are correctly calculated in the presence of
        soft failed events.

        Tests a graph like, where time flows down the page:

                A     B
               / \   /
              /   \ /
            SF1   SF2
             |     |
            SF3    |
           /   \   |
           |    \  |
           C     SF4

        Where SF* are soft failed, and with them A, B and C marked as
        extremities. This should resolve to B and C being marked as extremity.
        """

        # Create the room graph
        event_id_a = self.create_and_send_event(self.room_id, self.user)
        event_id_b = self.create_and_send_event(self.room_id, self.user)
        event_id_sf1 = self.create_and_send_event(
            self.room_id, self.user, True, [event_id_a]
        )
        event_id_sf2 = self.create_and_send_event(
            self.room_id, self.user, True, [event_id_a, event_id_b]
        )
        event_id_sf3 = self.create_and_send_event(
            self.room_id, self.user, True, [event_id_sf1]
        )
        self.create_and_send_event(
            self.room_id, self.user, True, [event_id_sf2, event_id_sf3]
        )  # SF4
        event_id_c = self.create_and_send_event(
            self.room_id, self.user, False, [event_id_sf3]
        )

        # Add the new extremity and check the latest events are as expected
        self.add_extremity(self.room_id, event_id_a)

        latest_event_ids = self.get_success(
            self.store.get_latest_event_ids_in_room(self.room_id)
        )
        self.assertEqual(
            set(latest_event_ids), set((event_id_a, event_id_b, event_id_c))
        )

        # Run the background update and check it did the right thing
        self.run_background_update()

        latest_event_ids = self.get_success(
            self.store.get_latest_event_ids_in_room(self.room_id)
        )
        self.assertEqual(set(latest_event_ids), set([event_id_b, event_id_c]))


class CleanupExtremDummyEventsTestCase(HomeserverTestCase):
    def make_homeserver(self, reactor, clock):
        config = self.default_config()
        config["cleanup_extremities_with_dummy_events"] = True
        return self.setup_test_homeserver(config=config)

    def prepare(self, reactor, clock, homeserver):
        self.store = homeserver.get_datastore()
        self.room_creator = homeserver.get_room_creation_handler()

        # Create a test user and room
        self.user = UserID("alice", "test")
        self.requester = Requester(self.user, None, False, None, None)
        info = self.get_success(self.room_creator.create_room(self.requester, {}))
        self.room_id = info["room_id"]

    def test_send_dummy_event(self):
        # Create a bushy graph with 50 extremities.

        event_id_start = self.create_and_send_event(self.room_id, self.user)

        for _ in range(50):
            self.create_and_send_event(
                self.room_id, self.user, prev_event_ids=[event_id_start]
            )

        latest_event_ids = self.get_success(
            self.store.get_latest_event_ids_in_room(self.room_id)
        )
        self.assertEqual(len(latest_event_ids), 50)

        # Pump the reactor repeatedly so that the background updates have a
        # chance to run.
        self.pump(10 * 60)

        latest_event_ids = self.get_success(
            self.store.get_latest_event_ids_in_room(self.room_id)
        )
        self.assertTrue(len(latest_event_ids) < 10, len(latest_event_ids))
