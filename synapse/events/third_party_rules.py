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

from typing import TYPE_CHECKING, Union

from synapse.events import EventBase
from synapse.events.snapshot import EventContext
from synapse.types import Requester, StateMap

if TYPE_CHECKING:
    from synapse.server import HomeServer


class ThirdPartyEventRules:
    """Allows server admins to provide a Python module implementing an extra
    set of rules to apply when processing events.

    This is designed to help admins of closed federations with enforcing custom
    behaviours.
    """

    def __init__(self, hs: "HomeServer"):
        self.third_party_rules = None

        self.store = hs.get_datastore()

        module = None
        config = None
        if hs.config.third_party_event_rules:
            module, config = hs.config.third_party_event_rules

        if module is not None:
            self.third_party_rules = module(
                config=config,
                module_api=hs.get_module_api(),
            )

    async def check_event_allowed(
        self, event: EventBase, context: EventContext
    ) -> Union[bool, dict]:
        """Check if a provided event should be allowed in the given context.

        The module can return:
            * True: the event is allowed.
            * False: the event is not allowed, and should be rejected with M_FORBIDDEN.
            * a dict: replacement event data.

        Args:
            event: The event to be checked.
            context: The context of the event.

        Returns:
            The result from the ThirdPartyRules module, as above
        """
        if self.third_party_rules is None:
            return True

        prev_state_ids = await context.get_prev_state_ids()

        # Retrieve the state events from the database.
        events = await self.store.get_events(prev_state_ids.values())
        state_events = {(ev.type, ev.state_key): ev for ev in events.values()}

        # Ensure that the event is frozen, to make sure that the module is not tempted
        # to try to modify it. Any attempt to modify it at this point will invalidate
        # the hashes and signatures.
        event.freeze()

        return await self.third_party_rules.check_event_allowed(event, state_events)

    async def on_create_room(
        self, requester: Requester, config: dict, is_requester_admin: bool
    ) -> bool:
        """Intercept requests to create room to allow, deny or update the
        request config.

        Args:
            requester
            config: The creation config from the client.
            is_requester_admin: If the requester is an admin

        Returns:
            Whether room creation is allowed or denied.
        """

        if self.third_party_rules is None:
            return True

        return await self.third_party_rules.on_create_room(
            requester, config, is_requester_admin
        )

    async def check_threepid_can_be_invited(
        self, medium: str, address: str, room_id: str
    ) -> bool:
        """Check if a provided 3PID can be invited in the given room.

        Args:
            medium: The 3PID's medium.
            address: The 3PID's address.
            room_id: The room we want to invite the threepid to.

        Returns:
            True if the 3PID can be invited, False if not.
        """

        if self.third_party_rules is None:
            return True

        state_events = await self._get_state_map_for_room(room_id)

        return await self.third_party_rules.check_threepid_can_be_invited(
            medium, address, state_events
        )

    async def check_visibility_can_be_modified(
        self, room_id: str, new_visibility: str
    ) -> bool:
        """Check if a room is allowed to be published to, or removed from, the public room
        list.

        Args:
            room_id: The ID of the room.
            new_visibility: The new visibility state. Either "public" or "private".

        Returns:
            True if the room's visibility can be modified, False if not.
        """
        if self.third_party_rules is None:
            return True

        check_func = getattr(
            self.third_party_rules, "check_visibility_can_be_modified", None
        )
        if not check_func or not callable(check_func):
            return True

        state_events = await self._get_state_map_for_room(room_id)

        return await check_func(room_id, state_events, new_visibility)

    async def _get_state_map_for_room(self, room_id: str) -> StateMap[EventBase]:
        """Given a room ID, return the state events of that room.

        Args:
            room_id: The ID of the room.

        Returns:
            A dict mapping (event type, state key) to state event.
        """
        state_ids = await self.store.get_filtered_current_state_ids(room_id)
        room_state_events = await self.store.get_events(state_ids.values())

        state_events = {}
        for key, event_id in state_ids.items():
            state_events[key] = room_state_events[event_id]

        return state_events
