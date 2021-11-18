# Copyright 2021 The Matrix.org Foundation C.I.C.
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

from typing import Dict, Optional

from twisted.test.proto_helpers import MemoryReactor

from synapse.api.constants import EventContentFields, EventTypes, RoomTypes
from synapse.rest import admin
from synapse.rest.client import login, room
from synapse.server import HomeServer
from synapse.types import JsonDict
from synapse.util import Clock

from tests import unittest


class SpaceDescendantsTestCase(unittest.HomeserverTestCase):
    """Tests iteration over the descendants of a space."""

    servlets = [
        admin.register_servlets_for_client_rest_resource,
        login.register_servlets,
        room.register_servlets,
    ]

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer):
        self.hs = hs
        self.handler = self.hs.get_space_hierarchy_handler()

        # Create a user.
        self.user = self.register_user("user", "pass")
        self.token = self.login("user", "pass")

        # Create a space and a child room.
        self.space = self.helper.create_room_as(
            self.user,
            tok=self.token,
            extra_content={
                "creation_content": {EventContentFields.ROOM_TYPE: RoomTypes.SPACE}
            },
        )
        self.room = self.helper.create_room_as(self.user, tok=self.token)
        self._add_child(self.space, self.room)

    def _add_child(
        self, space_id: str, room_id: str, order: Optional[str] = None
    ) -> None:
        """Adds a room to a space."""
        content: JsonDict = {"via": [self.hs.hostname]}
        if order is not None:
            content["order"] = order
        self.helper.send_state(
            space_id,
            event_type=EventTypes.SpaceChild,
            body=content,
            tok=self.token,
            state_key=room_id,
        )

    def _create_space(self) -> str:
        """Creates a space."""
        return self._create_room(
            extra_content={
                "creation_content": {EventContentFields.ROOM_TYPE: RoomTypes.SPACE}
            },
        )

    def _create_room(self, extra_content: Optional[Dict] = None) -> str:
        """Creates a room."""
        return self.helper.create_room_as(
            self.user,
            tok=self.token,
            extra_content=extra_content,
        )

    def test_empty_space(self):
        """Tests iteration over an empty space."""
        space_id = self._create_space()

        descendants, inaccessible_room_ids = self.get_success(
            self.handler.get_space_descendants(space_id)
        )

        self.assertEqual(descendants, [(space_id, [])])
        self.assertEqual(inaccessible_room_ids, [])

    def test_invalid_space(self):
        """Tests iteration over an inaccessible space."""
        space_id = f"!invalid:{self.hs.hostname}"

        descendants, inaccessible_room_ids = self.get_success(
            self.handler.get_space_descendants(space_id)
        )

        self.assertEqual(descendants, [(space_id, [])])
        self.assertEqual(inaccessible_room_ids, [space_id])

    def test_invalid_room(self):
        """Tests iteration over a space containing an inaccessible room."""
        space_id = self._create_space()
        room_id = f"!invalid:{self.hs.hostname}"
        self._add_child(space_id, room_id)

        descendants, inaccessible_room_ids = self.get_success(
            self.handler.get_space_descendants(space_id)
        )

        self.assertEqual(descendants, [(space_id, []), (room_id, [self.hs.hostname])])
        self.assertEqual(inaccessible_room_ids, [room_id])

    def test_cycle(self):
        """Tests iteration over a cyclic space."""
        # space_id
        #  - subspace_id
        #    - space_id
        space_id = self._create_space()
        subspace_id = self._create_space()
        self._add_child(space_id, subspace_id)
        self._add_child(subspace_id, space_id)

        descendants, inaccessible_room_ids = self.get_success(
            self.handler.get_space_descendants(space_id)
        )

        self.assertEqual(
            descendants, [(space_id, []), (subspace_id, [self.hs.hostname])]
        )
        self.assertEqual(inaccessible_room_ids, [])

    def test_duplicates(self):
        """Tests iteration over a space with repeated rooms."""
        # space_id
        #  - subspace_id
        #     - duplicate_room_1_id
        #     - duplicate_room_2_id
        #     - room_id
        #  - duplicate_room_1_id
        #  - duplicate_room_2_id
        space_id = self._create_space()
        subspace_id = self._create_space()
        room_id = self._create_room()
        duplicate_room_1_id = self._create_room()
        duplicate_room_2_id = self._create_room()
        self._add_child(space_id, subspace_id, order="1")
        self._add_child(space_id, duplicate_room_1_id, order="2")
        self._add_child(space_id, duplicate_room_2_id, order="3")
        self._add_child(subspace_id, duplicate_room_1_id, order="1")
        self._add_child(subspace_id, duplicate_room_2_id, order="2")
        self._add_child(subspace_id, room_id, order="3")

        descendants, inaccessible_room_ids = self.get_success(
            self.handler.get_space_descendants(space_id)
        )

        self.assertEqual(
            descendants,
            [
                (space_id, []),
                (subspace_id, [self.hs.hostname]),
                (room_id, [self.hs.hostname]),
                (duplicate_room_1_id, [self.hs.hostname]),
                (duplicate_room_2_id, [self.hs.hostname]),
            ],
        )
        self.assertEqual(inaccessible_room_ids, [])
