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
from typing import TYPE_CHECKING, Any, Awaitable, Callable, List, Optional, Tuple

from twisted.internet.defer import CancelledError

from synapse.api.errors import ModuleFailedException, SynapseError
from synapse.events import EventBase
from synapse.events.snapshot import EventContext
from synapse.storage.roommember import ProfileInfo
from synapse.types import Requester, StateMap
from synapse.util.async_helpers import delay_cancellation, maybe_awaitable

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


class ThirdPartyEventRules:
    """Allows server admins to provide a Python module implementing an extra
    set of rules to apply when processing events.

    This is designed to help admins of closed federations with enforcing custom
    behaviours.
    """

    def __init__(self, hs: "HomeServer"):
        self.third_party_rules = None

        self.store = hs.get_datastores().main
        self._storage_controllers = hs.get_storage_controllers()

        self._check_event_allowed_callbacks: List[CHECK_EVENT_ALLOWED_CALLBACK] = []
        self._on_create_room_callbacks: List[ON_CREATE_ROOM_CALLBACK] = []
        self._check_threepid_can_be_invited_callbacks: List[
            CHECK_THREEPID_CAN_BE_INVITED_CALLBACK
        ] = []
        self._check_visibility_can_be_modified_callbacks: List[
            CHECK_VISIBILITY_CAN_BE_MODIFIED_CALLBACK
        ] = []
        self._on_new_event_callbacks: List[ON_NEW_EVENT_CALLBACK] = []
        self._check_can_shutdown_room_callbacks: List[
            CHECK_CAN_SHUTDOWN_ROOM_CALLBACK
        ] = []
        self._check_can_deactivate_user_callbacks: List[
            CHECK_CAN_DEACTIVATE_USER_CALLBACK
        ] = []
        self._on_profile_update_callbacks: List[ON_PROFILE_UPDATE_CALLBACK] = []
        self._on_user_deactivation_status_changed_callbacks: List[
            ON_USER_DEACTIVATION_STATUS_CHANGED_CALLBACK
        ] = []
        self._on_threepid_bind_callbacks: List[ON_THREEPID_BIND_CALLBACK] = []

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
        on_new_event: Optional[ON_NEW_EVENT_CALLBACK] = None,
        check_can_shutdown_room: Optional[CHECK_CAN_SHUTDOWN_ROOM_CALLBACK] = None,
        check_can_deactivate_user: Optional[CHECK_CAN_DEACTIVATE_USER_CALLBACK] = None,
        on_profile_update: Optional[ON_PROFILE_UPDATE_CALLBACK] = None,
        on_user_deactivation_status_changed: Optional[
            ON_USER_DEACTIVATION_STATUS_CHANGED_CALLBACK
        ] = None,
        on_threepid_bind: Optional[ON_THREEPID_BIND_CALLBACK] = None,
    ) -> None:
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

        if on_new_event is not None:
            self._on_new_event_callbacks.append(on_new_event)

        if check_can_shutdown_room is not None:
            self._check_can_shutdown_room_callbacks.append(check_can_shutdown_room)

        if check_can_deactivate_user is not None:
            self._check_can_deactivate_user_callbacks.append(check_can_deactivate_user)
        if on_profile_update is not None:
            self._on_profile_update_callbacks.append(on_profile_update)

        if on_user_deactivation_status_changed is not None:
            self._on_user_deactivation_status_changed_callbacks.append(
                on_user_deactivation_status_changed,
            )

        if on_threepid_bind is not None:
            self._on_threepid_bind_callbacks.append(on_threepid_bind)

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
                res, replacement_data = await delay_cancellation(
                    callback(event, state_events)
                )
            except CancelledError:
                raise
            except SynapseError as e:
                # FIXME: Being able to throw SynapseErrors is relied upon by
                # some modules. PR #10386 accidentally broke this ability.
                # That said, we aren't keen on exposing this implementation detail
                # to modules and we should one day have a proper way to do what
                # is wanted.
                # This module callback needs a rework so that hacks such as
                # this one are not necessary.
                raise e
            except Exception:
                raise ModuleFailedException(
                    "Failed to run `check_event_allowed` module API callback"
                )

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
                threepid_can_be_invited = await delay_cancellation(
                    callback(medium, address, state_events)
                )
                if threepid_can_be_invited is False:
                    return False
            except CancelledError:
                raise
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
                visibility_can_be_modified = await delay_cancellation(
                    callback(room_id, state_events, new_visibility)
                )
                if visibility_can_be_modified is False:
                    return False
            except CancelledError:
                raise
            except Exception as e:
                logger.warning("Failed to run module API callback %s: %s", callback, e)

        return True

    async def on_new_event(self, event_id: str) -> None:
        """Let modules act on events after they've been sent (e.g. auto-accepting
        invites, etc.)

        Args:
            event_id: The ID of the event.
        """
        # Bail out early without hitting the store if we don't have any callbacks
        if len(self._on_new_event_callbacks) == 0:
            return

        event = await self.store.get_event(event_id)
        state_events = await self._get_state_map_for_room(event.room_id)

        for callback in self._on_new_event_callbacks:
            try:
                await callback(event, state_events)
            except Exception as e:
                logger.exception(
                    "Failed to run module API callback %s: %s", callback, e
                )

    async def check_can_shutdown_room(self, user_id: str, room_id: str) -> bool:
        """Intercept requests to shutdown a room. If `False` is returned, the
         room must not be shut down.

        Args:
            requester: The ID of the user requesting the shutdown.
            room_id: The ID of the room.
        """
        for callback in self._check_can_shutdown_room_callbacks:
            try:
                can_shutdown_room = await delay_cancellation(callback(user_id, room_id))
                if can_shutdown_room is False:
                    return False
            except CancelledError:
                raise
            except Exception as e:
                logger.exception(
                    "Failed to run module API callback %s: %s", callback, e
                )
        return True

    async def check_can_deactivate_user(
        self,
        user_id: str,
        by_admin: bool,
    ) -> bool:
        """Intercept requests to deactivate a user. If `False` is returned, the
        user should not be deactivated.

        Args:
            requester
            user_id: The ID of the room.
        """
        for callback in self._check_can_deactivate_user_callbacks:
            try:
                can_deactivate_user = await delay_cancellation(
                    callback(user_id, by_admin)
                )
                if can_deactivate_user is False:
                    return False
            except CancelledError:
                raise
            except Exception as e:
                logger.exception(
                    "Failed to run module API callback %s: %s", callback, e
                )
        return True

    async def _get_state_map_for_room(self, room_id: str) -> StateMap[EventBase]:
        """Given a room ID, return the state events of that room.

        Args:
            room_id: The ID of the room.

        Returns:
            A dict mapping (event type, state key) to state event.
        """
        return await self._storage_controllers.state.get_current_state(room_id)

    async def on_profile_update(
        self, user_id: str, new_profile: ProfileInfo, by_admin: bool, deactivation: bool
    ) -> None:
        """Called after the global profile of a user has been updated. Does not include
        per-room profile changes.

        Args:
            user_id: The user whose profile was changed.
            new_profile: The updated profile for the user.
            by_admin: Whether the profile update was performed by a server admin.
            deactivation: Whether this change was made while deactivating the user.
        """
        for callback in self._on_profile_update_callbacks:
            try:
                await callback(user_id, new_profile, by_admin, deactivation)
            except Exception as e:
                logger.exception(
                    "Failed to run module API callback %s: %s", callback, e
                )

    async def on_user_deactivation_status_changed(
        self, user_id: str, deactivated: bool, by_admin: bool
    ) -> None:
        """Called after a user has been deactivated or reactivated.

        Args:
            user_id: The deactivated user.
            deactivated: Whether the user is now deactivated.
            by_admin: Whether the deactivation was performed by a server admin.
        """
        for callback in self._on_user_deactivation_status_changed_callbacks:
            try:
                await callback(user_id, deactivated, by_admin)
            except Exception as e:
                logger.exception(
                    "Failed to run module API callback %s: %s", callback, e
                )

    async def on_threepid_bind(self, user_id: str, medium: str, address: str) -> None:
        """Called after a threepid association has been verified and stored.

        Note that this callback is called when an association is created on the
        local homeserver, not when it's created on an identity server (and then kept track
        of so that it can be unbound on the same IS later on).

        Args:
            user_id: the user being associated with the threepid.
            medium: the threepid's medium.
            address: the threepid's address.
        """
        for callback in self._on_threepid_bind_callbacks:
            try:
                await callback(user_id, medium, address)
            except Exception as e:
                logger.exception(
                    "Failed to run module API callback %s: %s", callback, e
                )
