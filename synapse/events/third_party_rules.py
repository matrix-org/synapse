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
import logging
from typing import TYPE_CHECKING, Awaitable, Callable, List, Optional, Tuple

from synapse.api.errors import SynapseError
from synapse.events import EventBase
from synapse.events.snapshot import EventContext
from synapse.types import Requester, StateMap
from synapse.util.async_helpers import maybe_awaitable

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


CHECK_EVENT_ALLOWED_CALLBACK = Callable[
    [EventBase, StateMap[EventBase]], Awaitable[Tuple[bool, Optional[dict]]]
]
ON_CREATE_ROOM_CALLBACK = Callable[[Requester, dict, bool], Awaitable]
CHECK_THREEPID_CAN_BE_INVITED_CALLBACK = Callable[
    [str, str, StateMap[EventBase]], Awaitable[bool]
]
CHECK_VISIBILITY_CAN_BE_MODIFIED_CALLBACK = Callable[
    [str, StateMap[EventBase], str], Awaitable[bool]
]


def load_legacy_third_party_event_rules(hs: "HomeServer"):
    """Wrapper that loads a third party event rules module configured using the old
    configuration, and registers the hooks they implement.
    """
    if hs.config.third_party_event_rules is None:
        return

    module, config = hs.config.third_party_event_rules

    api = hs.get_module_api()
    third_party_rules = module(config=config, module_api=api)

    # The known hooks. If a module implements a method which name appears in this set,
    # we'll want to register it.
    third_party_event_rules_methods = {
        "check_event_allowed",
        "on_create_room",
        "check_threepid_can_be_invited",
        "check_visibility_can_be_modified",
    }

    def async_wrapper(f: Optional[Callable]) -> Optional[Callable[..., Awaitable]]:
        # f might be None if the callback isn't implemented by the module. In this
        # case we don't want to register a callback at all so we return None.
        if f is None:
            return None

        # We return a separate wrapper for these methods because, in order to wrap them
        # correctly, we need to await its result. Therefore it doesn't make a lot of
        # sense to make it go through the run() wrapper.
        if f.__name__ == "check_event_allowed":

            # We need to wrap check_event_allowed because its old form would return either
            # a boolean or a dict, but now we want to return the dict separately from the
            # boolean.
            async def wrap_check_event_allowed(
                event: EventBase,
                state_events: StateMap[EventBase],
            ) -> Tuple[bool, Optional[dict]]:
                # We've already made sure f is not None above, but mypy doesn't do well
                # across function boundaries so we need to tell it f is definitely not
                # None.
                assert f is not None

                res = await f(event, state_events)
                if isinstance(res, dict):
                    return True, res
                else:
                    return res, None

            return wrap_check_event_allowed

        if f.__name__ == "on_create_room":

            # We need to wrap on_create_room because its old form would return a boolean
            # if the room creation is denied, but now we just want it to raise an
            # exception.
            async def wrap_on_create_room(
                requester: Requester, config: dict, is_requester_admin: bool
            ) -> None:
                # We've already made sure f is not None above, but mypy doesn't do well
                # across function boundaries so we need to tell it f is definitely not
                # None.
                assert f is not None

                res = await f(requester, config, is_requester_admin)
                if res is False:
                    raise SynapseError(
                        403,
                        "Room creation forbidden with these parameters",
                    )

            return wrap_on_create_room

        def run(*args, **kwargs):
            # mypy doesn't do well across function boundaries so we need to tell it
            # f is definitely not None.
            assert f is not None

            return maybe_awaitable(f(*args, **kwargs))

        return run

    # Register the hooks through the module API.
    hooks = {
        hook: async_wrapper(getattr(third_party_rules, hook, None))
        for hook in third_party_event_rules_methods
    }

    api.register_third_party_rules_callbacks(**hooks)


class ThirdPartyEventRules:
    """Allows server admins to provide a Python module implementing an extra
    set of rules to apply when processing events.

    This is designed to help admins of closed federations with enforcing custom
    behaviours.
    """

    def __init__(self, hs: "HomeServer"):
        self.third_party_rules = None

        self.store = hs.get_datastore()

        self._check_event_allowed_callbacks: List[CHECK_EVENT_ALLOWED_CALLBACK] = []
        self._on_create_room_callbacks: List[ON_CREATE_ROOM_CALLBACK] = []
        self._check_threepid_can_be_invited_callbacks: List[
            CHECK_THREEPID_CAN_BE_INVITED_CALLBACK
        ] = []
        self._check_visibility_can_be_modified_callbacks: List[
            CHECK_VISIBILITY_CAN_BE_MODIFIED_CALLBACK
        ] = []

    def register_third_party_rules_callbacks(
        self,
        check_event_allowed: Optional[CHECK_EVENT_ALLOWED_CALLBACK] = None,
        on_create_room: Optional[ON_CREATE_ROOM_CALLBACK] = None,
        check_threepid_can_be_invited: Optional[
            CHECK_THREEPID_CAN_BE_INVITED_CALLBACK
        ] = None,
        check_visibility_can_be_modified: Optional[
            CHECK_VISIBILITY_CAN_BE_MODIFIED_CALLBACK
        ] = None,
    ):
        """Register callbacks from modules for each hook."""
        if check_event_allowed is not None:
            self._check_event_allowed_callbacks.append(check_event_allowed)

        if on_create_room is not None:
            self._on_create_room_callbacks.append(on_create_room)

        if check_threepid_can_be_invited is not None:
            self._check_threepid_can_be_invited_callbacks.append(
                check_threepid_can_be_invited,
            )

        if check_visibility_can_be_modified is not None:
            self._check_visibility_can_be_modified_callbacks.append(
                check_visibility_can_be_modified,
            )

    async def check_event_allowed(
        self, event: EventBase, context: EventContext
    ) -> Tuple[bool, Optional[dict]]:
        """Check if a provided event should be allowed in the given context.

        The module can return:
            * True: the event is allowed.
            * False: the event is not allowed, and should be rejected with M_FORBIDDEN.

        If the event is allowed, the module can also return a dictionary to use as a
        replacement for the event.

        Args:
            event: The event to be checked.
            context: The context of the event.

        Returns:
            The result from the ThirdPartyRules module, as above.
        """
        # Bail out early without hitting the store if we don't have any callbacks to run.
        if len(self._check_event_allowed_callbacks) == 0:
            return True, None

        prev_state_ids = await context.get_prev_state_ids()

        # Retrieve the state events from the database.
        events = await self.store.get_events(prev_state_ids.values())
        state_events = {(ev.type, ev.state_key): ev for ev in events.values()}

        # Ensure that the event is frozen, to make sure that the module is not tempted
        # to try to modify it. Any attempt to modify it at this point will invalidate
        # the hashes and signatures.
        event.freeze()

        for callback in self._check_event_allowed_callbacks:
            try:
                res, replacement_data = await callback(event, state_events)
            except Exception as e:
                logger.warning("Failed to run module API callback %s: %s", callback, e)
                continue

            # Return if the event shouldn't be allowed or if the module came up with a
            # replacement dict for the event.
            if res is False:
                return res, None
            elif isinstance(replacement_data, dict):
                return True, replacement_data

        return True, None

    async def on_create_room(
        self, requester: Requester, config: dict, is_requester_admin: bool
    ) -> None:
        """Intercept requests to create room to maybe deny it (via an exception) or
        update the request config.

        Args:
            requester
            config: The creation config from the client.
            is_requester_admin: If the requester is an admin
        """
        for callback in self._on_create_room_callbacks:
            try:
                await callback(requester, config, is_requester_admin)
            except Exception as e:
                # Don't silence the errors raised by this callback since we expect it to
                # raise an exception to deny the creation of the room; instead make sure
                # it's a SynapseError we can send to clients.
                if not isinstance(e, SynapseError):
                    e = SynapseError(
                        403, "Room creation forbidden with these parameters"
                    )

                raise e

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
        # Bail out early without hitting the store if we don't have any callbacks to run.
        if len(self._check_threepid_can_be_invited_callbacks) == 0:
            return True

        state_events = await self._get_state_map_for_room(room_id)

        for callback in self._check_threepid_can_be_invited_callbacks:
            try:
                if await callback(medium, address, state_events) is False:
                    return False
            except Exception as e:
                logger.warning("Failed to run module API callback %s: %s", callback, e)

        return True

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
        # Bail out early without hitting the store if we don't have any callback
        if len(self._check_visibility_can_be_modified_callbacks) == 0:
            return True

        state_events = await self._get_state_map_for_room(room_id)

        for callback in self._check_visibility_can_be_modified_callbacks:
            try:
                if await callback(room_id, state_events, new_visibility) is False:
                    return False
            except Exception as e:
                logger.warning("Failed to run module API callback %s: %s", callback, e)

        return True

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
