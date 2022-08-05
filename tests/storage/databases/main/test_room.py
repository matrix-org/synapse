# Copyright 2021 The Matrix.org Foundation C.I.C.
#
# Licensed under the Apache License, Version 2.0 (the 'License');
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an 'AS IS' BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import json

from synapse.api.constants import RoomTypes
from synapse.rest import admin
from synapse.rest.client import login, room
from synapse.storage.databases.main.room import _BackgroundUpdates

from tests.unittest import HomeserverTestCase


class RoomBackgroundUpdateStoreTestCase(HomeserverTestCase):

    servlets = [
        admin.register_servlets,
        room.register_servlets,
        login.register_servlets,
    ]

    def prepare(self, reactor, clock, hs):
        self.store = hs.get_datastores().main
        self.user_id = self.register_user("foo", "pass")
        self.token = self.login("foo", "pass")

    def _generate_room(self) -> str:
        room_id = self.helper.create_room_as(self.user_id, tok=self.token)

        return room_id

    def test_background_populate_rooms_creator_column(self):
        """Test that the background update to populate the rooms creator column
        works properly.
        """

        # Insert a room without the creator
        room_id = self._generate_room()
        self.get_success(
            self.store.db_pool.simple_update(
                table="rooms",
                keyvalues={"room_id": room_id},
                updatevalues={"creator": None},
                desc="test",
            )
        )

        # Make sure the test is starting out with a room without a creator
        room_creator_before = self.get_success(
            self.store.db_pool.simple_select_one_onecol(
                table="rooms",
                keyvalues={"room_id": room_id},
                retcol="creator",
                allow_none=True,
            )
        )
        self.assertEqual(room_creator_before, None)

        # Insert and run the background update.
        self.get_success(
            self.store.db_pool.simple_insert(
                "background_updates",
                {
                    "update_name": _BackgroundUpdates.POPULATE_ROOMS_CREATOR_COLUMN,
                    "progress_json": "{}",
                },
            )
        )

        # ... and tell the DataStore that it hasn't finished all updates yet
        self.store.db_pool.updates._all_done = False

        # Now let's actually drive the updates to completion
        self.wait_for_background_updates()

        # Make sure the background update filled in the room creator
        room_creator_after = self.get_success(
            self.store.db_pool.simple_select_one_onecol(
                table="rooms",
                keyvalues={"room_id": room_id},
                retcol="creator",
                allow_none=True,
            )
        )
        self.assertEqual(room_creator_after, self.user_id)

    def test_background_add_room_type_column(self):
        """Test that the background update to populate the `room_type` column in
        `room_stats_state` works properly.
        """

        # Create a room without a type
        room_id = self._generate_room()

        # Get event_id of the m.room.create event
        event_id = self.get_success(
            self.store.db_pool.simple_select_one_onecol(
                table="current_state_events",
                keyvalues={
                    "room_id": room_id,
                    "type": "m.room.create",
                },
                retcol="event_id",
            )
        )

        # Fake a room creation event with a room type
        event = {
            "content": {
                "creator": "@user:server.org",
                "room_version": "9",
                "type": RoomTypes.SPACE,
            },
            "type": "m.room.create",
        }
        self.get_success(
            self.store.db_pool.simple_update(
                table="event_json",
                keyvalues={"event_id": event_id},
                updatevalues={"json": json.dumps(event)},
                desc="test",
            )
        )

        # Insert and run the background update
        self.get_success(
            self.store.db_pool.simple_insert(
                "background_updates",
                {
                    "update_name": _BackgroundUpdates.ADD_ROOM_TYPE_COLUMN,
                    "progress_json": "{}",
                },
            )
        )

        # ... and tell the DataStore that it hasn't finished all updates yet
        self.store.db_pool.updates._all_done = False

        # Now let's actually drive the updates to completion
        self.wait_for_background_updates()

        # Make sure the background update filled in the room type
        room_type_after = self.get_success(
            self.store.db_pool.simple_select_one_onecol(
                table="room_stats_state",
                keyvalues={"room_id": room_id},
                retcol="room_type",
                allow_none=True,
            )
        )
        self.assertEqual(room_type_after, RoomTypes.SPACE)
