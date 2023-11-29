# Copyright 2023 The Matrix.org Foundation C.I.C.
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
from twisted.test.proto_helpers import MemoryReactor

from synapse.events import EventBase
from synapse.rest import admin, login, room
from synapse.server import HomeServer
from synapse.types import JsonDict
from synapse.util import Clock

from tests.unittest import HomeserverTestCase


class EventUnsignedAdditionTestCase(HomeserverTestCase):
    servlets = [
        room.register_servlets,
        admin.register_servlets,
        login.register_servlets,
    ]

    def prepare(
        self, reactor: MemoryReactor, clock: Clock, homeserver: HomeServer
    ) -> None:
        self._store = homeserver.get_datastores().main
        self._module_api = homeserver.get_module_api()
        self._account_data_mgr = self._module_api.account_data_manager

    def test_annotate_event(self) -> None:
        """Test that we can annotate an event when we request it from the
        server.
        """

        async def add_unsigned_event(event: EventBase) -> JsonDict:
            return {"test_key": event.event_id}

        self._module_api.register_add_extra_fields_to_unsigned_client_event_callbacks(
            add_field_to_unsigned_callback=add_unsigned_event
        )

        user_id = self.register_user("user", "password")
        token = self.login("user", "password")

        room_id = self.helper.create_room_as(user_id, tok=token)
        result = self.helper.send(room_id, "Hello!", tok=token)
        event_id = result["event_id"]

        event_json = self.helper.get_event(room_id, event_id, tok=token)
        self.assertEqual(event_json["unsigned"].get("test_key"), event_id)
