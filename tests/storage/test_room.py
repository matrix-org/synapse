# -*- coding: utf-8 -*-
# Copyright 2014-2021 The Matrix.org Foundation C.I.C.
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

from synapse.api.constants import EventTypes
from synapse.api.room_versions import RoomVersions
from synapse.types import RoomAlias, RoomID, UserID

from tests.unittest import HomeserverTestCase


class RoomStoreTestCase(HomeserverTestCase):
    def prepare(self, reactor, clock, hs):
        # We can't test RoomStore on its own without the DirectoryStore, for
        # management of the 'room_aliases' table
        self.store = hs.get_datastore()

        self.room = RoomID.from_string("!abcde:test")
        self.alias = RoomAlias.from_string("#a-room-name:test")
        self.u_creator = UserID.from_string("@creator:test")

        self.get_success(
            self.store.store_room(
                self.room.to_string(),
                room_creator_user_id=self.u_creator.to_string(),
                is_public=True,
                room_version=RoomVersions.V1,
            )
        )

    def test_get_room(self):
        self.assertDictContainsSubset(
            {
                "room_id": self.room.to_string(),
                "creator": self.u_creator.to_string(),
                "is_public": True,
            },
            (self.get_success(self.store.get_room(self.room.to_string()))),
        )

    def test_get_room_unknown_room(self):
        self.assertIsNone((self.get_success(self.store.get_room("!uknown:test"))))

    def test_get_room_with_stats(self):
        self.assertDictContainsSubset(
            {
                "room_id": self.room.to_string(),
                "creator": self.u_creator.to_string(),
                "public": True,
            },
            (self.get_success(self.store.get_room_with_stats(self.room.to_string()))),
        )

    def test_get_room_with_stats_unknown_room(self):
        self.assertIsNone(
            (self.get_success(self.store.get_room_with_stats("!uknown:test"))),
        )


class RoomEventsStoreTestCase(HomeserverTestCase):
    def prepare(self, reactor, clock, hs):
        # Room events need the full datastore, for persist_event() and
        # get_room_state()
        self.store = hs.get_datastore()
        self.storage = hs.get_storage()
        self.event_factory = hs.get_event_factory()

        self.room = RoomID.from_string("!abcde:test")

        self.get_success(
            self.store.store_room(
                self.room.to_string(),
                room_creator_user_id="@creator:text",
                is_public=True,
                room_version=RoomVersions.V1,
            )
        )

    def inject_room_event(self, **kwargs):
        self.get_success(
            self.storage.persistence.persist_event(
                self.event_factory.create_event(room_id=self.room.to_string(), **kwargs)
            )
        )

    def STALE_test_room_name(self):
        name = "A-Room-Name"

        self.inject_room_event(
            etype=EventTypes.Name, name=name, content={"name": name}, depth=1
        )

        state = self.get_success(
            self.store.get_current_state(room_id=self.room.to_string())
        )

        self.assertEquals(1, len(state))
        self.assertObjectHasAttributes(
            {"type": "m.room.name", "room_id": self.room.to_string(), "name": name},
            state[0],
        )

    def STALE_test_room_topic(self):
        topic = "A place for things"

        self.inject_room_event(
            etype=EventTypes.Topic, topic=topic, content={"topic": topic}, depth=1
        )

        state = self.get_success(
            self.store.get_current_state(room_id=self.room.to_string())
        )

        self.assertEquals(1, len(state))
        self.assertObjectHasAttributes(
            {"type": "m.room.topic", "room_id": self.room.to_string(), "topic": topic},
            state[0],
        )

    # Not testing the various 'level' methods for now because there's lots
    # of them and need coalescing; see JIRA SPEC-11
