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

from synapse.rest.client.v1 import admin, login, room

from tests import unittest


class StatsRoomTests(unittest.HomeserverTestCase):

    servlets = [
        admin.register_servlets,
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
                {
                    "update_name": "populate_stats_createtables",
                    "progress_json": "{}",
                },
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
        self.hs.config.stats_enable = False
        self.handler.stats_enable = False

        u1 = self.register_user("u1", "pass")
        u1_token = self.login("u1", "pass")

        room_1 = self.helper.create_room_as(u1, tok=u1_token)
        self.helper.send_state(
            room_1, event_type="m.room.topic", body={"topic": "foo"}, tok=u1_token
        )

        # Enable stats
        self.hs.config.stats_enable = True
        self.handler.stats_enable = True

        # Do the initial population of the user directory via the background update
        self._add_background_updates()

        while not self.get_success(self.store.has_completed_background_updates()):
            self.get_success(self.store.do_next_background_update(100), by=0.1)

        r = self.get_success(self.store.get_all_room_state())

        self.assertEqual(len(r), 1)
        self.assertEqual(r[0]["topic"], "foo")
