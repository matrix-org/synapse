# Copyright 2019, 2023 The Matrix.org Foundation C.I.C.
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
from typing import TYPE_CHECKING, Any, Awaitable, Callable, List, Optional, Tuple

from synapse.api.errors import SynapseError
from synapse.events import EventBase
from synapse.storage.roommember import ProfileInfo
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
ON_NEW_EVENT_CALLBACK = Callable[[EventBase, StateMap[EventBase]], Awaitable]
CHECK_CAN_SHUTDOWN_ROOM_CALLBACK = Callable[[str, str], Awaitable[bool]]
CHECK_CAN_DEACTIVATE_USER_CALLBACK = Callable[[str, bool], Awaitable[bool]]
ON_PROFILE_UPDATE_CALLBACK = Callable[[str, ProfileInfo, bool, bool], Awaitable]
ON_USER_DEACTIVATION_STATUS_CHANGED_CALLBACK = Callable[[str, bool, bool], Awaitable]
ON_THREEPID_BIND_CALLBACK = Callable[[str, str, str], Awaitable]
ON_ADD_USER_THIRD_PARTY_IDENTIFIER_CALLBACK = Callable[[str, str, str], Awaitable]
ON_REMOVE_USER_THIRD_PARTY_IDENTIFIER_CALLBACK = Callable[[str, str, str], Awaitable]


def load_legacy_third_party_event_rules(hs: "HomeServer") -> None:
    """Wrapper that loads a third party event rules module configured using the old
    configuration, and registers the hooks they implement.
    """
    if hs.config.thirdpartyrules.third_party_event_rules is None:
        return

    module, config = hs.config.thirdpartyrules.third_party_event_rules

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
                # Assertion required because mypy can't prove we won't change
                # `f` back to `None`. See
                # https://mypy.readthedocs.io/en/latest/common_issues.html#narrowing-and-inner-functions
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
                # Assertion required because mypy can't prove we won't change
                # `f` back to `None`. See
                # https://mypy.readthedocs.io/en/latest/common_issues.html#narrowing-and-inner-functions
                assert f is not None

                res = await f(requester, config, is_requester_admin)
                if res is False:
                    raise SynapseError(
                        403,
                        "Room creation forbidden with these parameters",
                    )

            return wrap_on_create_room

        def run(*args: Any, **kwargs: Any) -> Awaitable:
            # Assertion required because mypy can't prove we won't change  `f`
            # back to `None`. See
            # https://mypy.readthedocs.io/en/latest/common_issues.html#narrowing-and-inner-functions
            assert f is not None

            return maybe_awaitable(f(*args, **kwargs))

        return run

    # Register the hooks through the module API.
    hooks = {
        hook: async_wrapper(getattr(third_party_rules, hook, None))
        for hook in third_party_event_rules_methods
    }

    api.register_third_party_rules_callbacks(**hooks)


class ThirdPartyEventRulesModuleApiCallbacks:
    def __init__(self) -> None:
        self.check_event_allowed_callbacks: List[CHECK_EVENT_ALLOWED_CALLBACK] = []
        self.on_create_room_callbacks: List[ON_CREATE_ROOM_CALLBACK] = []
        self.check_threepid_can_be_invited_callbacks: List[
            CHECK_THREEPID_CAN_BE_INVITED_CALLBACK
        ] = []
        self.check_visibility_can_be_modified_callbacks: List[
            CHECK_VISIBILITY_CAN_BE_MODIFIED_CALLBACK
        ] = []
        self.on_new_event_callbacks: List[ON_NEW_EVENT_CALLBACK] = []
        self.check_can_shutdown_room_callbacks: List[
            CHECK_CAN_SHUTDOWN_ROOM_CALLBACK
        ] = []
        self.check_can_deactivate_user_callbacks: List[
            CHECK_CAN_DEACTIVATE_USER_CALLBACK
        ] = []
        self.on_profile_update_callbacks: List[ON_PROFILE_UPDATE_CALLBACK] = []
        self.on_user_deactivation_status_changed_callbacks: List[
            ON_USER_DEACTIVATION_STATUS_CHANGED_CALLBACK
        ] = []
        self.on_threepid_bind_callbacks: List[ON_THREEPID_BIND_CALLBACK] = []
        self.on_add_user_third_party_identifier_callbacks: List[
            ON_ADD_USER_THIRD_PARTY_IDENTIFIER_CALLBACK
        ] = []
        self.on_remove_user_third_party_identifier_callbacks: List[
            ON_REMOVE_USER_THIRD_PARTY_IDENTIFIER_CALLBACK
        ] = []

    def register_callbacks(
        self,
        check_event_allowed: Optional[CHECK_EVENT_ALLOWED_CALLBACK] = None,
        on_create_room: Optional[ON_CREATE_ROOM_CALLBACK] = None,
        check_threepid_can_be_invited: Optional[
            CHECK_THREEPID_CAN_BE_INVITED_CALLBACK
        ] = None,
        check_visibility_can_be_modified: Optional[
            CHECK_VISIBILITY_CAN_BE_MODIFIED_CALLBACK
        ] = None,
        on_new_event: Optional[ON_NEW_EVENT_CALLBACK] = None,
        check_can_shutdown_room: Optional[CHECK_CAN_SHUTDOWN_ROOM_CALLBACK] = None,
        check_can_deactivate_user: Optional[CHECK_CAN_DEACTIVATE_USER_CALLBACK] = None,
        on_profile_update: Optional[ON_PROFILE_UPDATE_CALLBACK] = None,
        on_user_deactivation_status_changed: Optional[
            ON_USER_DEACTIVATION_STATUS_CHANGED_CALLBACK
        ] = None,
        on_threepid_bind: Optional[ON_THREEPID_BIND_CALLBACK] = None,
        on_add_user_third_party_identifier: Optional[
            ON_ADD_USER_THIRD_PARTY_IDENTIFIER_CALLBACK
        ] = None,
        on_remove_user_third_party_identifier: Optional[
            ON_REMOVE_USER_THIRD_PARTY_IDENTIFIER_CALLBACK
        ] = None,
    ) -> None:
        """Register callbacks from modules for each hook."""
        if check_event_allowed is not None:
            self.check_event_allowed_callbacks.append(check_event_allowed)

        if on_create_room is not None:
            self.on_create_room_callbacks.append(on_create_room)

        if check_threepid_can_be_invited is not None:
            self.check_threepid_can_be_invited_callbacks.append(
                check_threepid_can_be_invited,
            )

        if check_visibility_can_be_modified is not None:
            self.check_visibility_can_be_modified_callbacks.append(
                check_visibility_can_be_modified,
            )

        if on_new_event is not None:
            self.on_new_event_callbacks.append(on_new_event)

        if check_can_shutdown_room is not None:
            self.check_can_shutdown_room_callbacks.append(check_can_shutdown_room)

        if check_can_deactivate_user is not None:
            self.check_can_deactivate_user_callbacks.append(check_can_deactivate_user)

        if on_profile_update is not None:
            self.on_profile_update_callbacks.append(on_profile_update)

        if on_user_deactivation_status_changed is not None:
            self.on_user_deactivation_status_changed_callbacks.append(
                on_user_deactivation_status_changed,
            )

        if on_threepid_bind is not None:
            self.on_threepid_bind_callbacks.append(on_threepid_bind)

        if on_add_user_third_party_identifier is not None:
            self.on_add_user_third_party_identifier_callbacks.append(
                on_add_user_third_party_identifier
            )

        if on_remove_user_third_party_identifier is not None:
            self.on_remove_user_third_party_identifier_callbacks.append(
                on_remove_user_third_party_identifier
            )
