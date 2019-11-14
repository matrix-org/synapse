# -*- coding: utf-8 -*-
# Copyright 2018 New Vector Ltd
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

from synapse.rest.client.v1 import room

from tests.unittest import HomeserverTestCase


class PurgeTests(HomeserverTestCase):

    user_id = "@red:server"
    servlets = [room.register_servlets]

    def make_homeserver(self, reactor, clock):
        hs = self.setup_test_homeserver("server", http_client=None)
        return hs

    def prepare(self, reactor, clock, hs):
        self.room_id = self.helper.create_room_as(self.user_id)

    def test_purge(self):
        """
        Purging a room will delete everything before the topological point.
        """
        # Send four messages to the room
        first = self.helper.send(self.room_id, body="test1")
        second = self.helper.send(self.room_id, body="test2")
        third = self.helper.send(self.room_id, body="test3")
        last = self.helper.send(self.room_id, body="test4")

        store = self.hs.get_datastore()
        storage = self.hs.get_storage()

        # Get the topological token
        event = store.get_topological_token_for_event(last["event_id"])
        self.pump()
        event = self.successResultOf(event)

        # Purge everything before this topological token
        purge = storage.purge_events.purge_history(self.room_id, event, True)
        self.pump()
        self.assertEqual(self.successResultOf(purge), None)

        # Try and get the events
        get_first = store.get_event(first["event_id"])
        get_second = store.get_event(second["event_id"])
        get_third = store.get_event(third["event_id"])
        get_last = store.get_event(last["event_id"])
        self.pump()

        # 1-3 should fail and last will succeed, meaning that 1-3 are deleted
        # and last is not.
        self.failureResultOf(get_first)
        self.failureResultOf(get_second)
        self.failureResultOf(get_third)
        self.successResultOf(get_last)

    def test_purge_wont_delete_extrems(self):
        """
        Purging a room will delete everything before the topological point.
        """
        # Send four messages to the room
        first = self.helper.send(self.room_id, body="test1")
        second = self.helper.send(self.room_id, body="test2")
        third = self.helper.send(self.room_id, body="test3")
        last = self.helper.send(self.room_id, body="test4")

        storage = self.hs.get_datastore()

        # Set the topological token higher than it should be
        event = storage.get_topological_token_for_event(last["event_id"])
        self.pump()
        event = self.successResultOf(event)
        event = "t{}-{}".format(
            *list(map(lambda x: x + 1, map(int, event[1:].split("-"))))
        )

        # Purge everything before this topological token
        purge = storage.purge_history(self.room_id, event, True)
        self.pump()
        f = self.failureResultOf(purge)
        self.assertIn("greater than forward", f.value.args[0])

        # Try and get the events
        get_first = storage.get_event(first["event_id"])
        get_second = storage.get_event(second["event_id"])
        get_third = storage.get_event(third["event_id"])
        get_last = storage.get_event(last["event_id"])
        self.pump()

        # Nothing is deleted.
        self.successResultOf(get_first)
        self.successResultOf(get_second)
        self.successResultOf(get_third)
        self.successResultOf(get_last)
