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

    def test_initial_room(self):
        """
        initial_room_spam will build the table from scratch.
        """
        r = self.get_success(self.store.get_all_room_state())
        self.assertEqual(len(r), 0)

        self.get_success(self.store.update_stats_stream_pos(None))

        # Disable stats
        self.hs.config.stats_enable = False

        u1 = self.register_user("u1", "pass")
        u1_token = self.login("u1", "pass")

        room_1 = self.helper.create_room_as(u1, tok=u1_token)
        self.helper.send_state(
            room_1, event_type="m.room.topic", body={"topic": "foo"}, tok=u1_token
        )

        # Enable stats
        self.hs.config.stats_enable = True
        self.handler.notify_new_event()
        self.pump(10)

        r = self.get_success(self.store.get_all_room_state())

        self.assertEqual(len(r), 1)
        self.assertEqual(r[0]["topic"], "foo")
