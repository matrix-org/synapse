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
import logging
from typing import TYPE_CHECKING, Collection, List, Mapping, Optional, Union

from synapse import event_auth
from synapse.api.constants import (
    EventTypes,
    JoinRules,
    Membership,
    RestrictedJoinRuleTypes,
)
from synapse.api.errors import AuthError, Codes, SynapseError
from synapse.api.room_versions import RoomVersion
from synapse.event_auth import (
    check_state_dependent_auth_rules,
    check_state_independent_auth_rules,
)
from synapse.events import EventBase
from synapse.events.builder import EventBuilder
from synapse.types import StateMap, get_domain_from_id

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


class EventAuthHandler:
    """
    This class contains methods for authenticating events added to room graphs.
    """

    def __init__(self, hs: "HomeServer"):
        self._clock = hs.get_clock()
        self._store = hs.get_datastores().main
        self._server_name = hs.hostname

    async def check_auth_rules_from_context(
        self,
        event: EventBase,
        batched_auth_events: Optional[Mapping[str, EventBase]] = None,
    ) -> None:
        """Check an event passes the auth rules at its own auth events
        Args:
            event: event to be authed
            batched_auth_events: if the event being authed is part of a batch, any events
            from the same batch that may be necessary to auth the current event
        """
        await check_state_independent_auth_rules(
            self._store, event, batched_auth_events
        )
        auth_event_ids = event.auth_event_ids()
        auth_events_by_id = await self._store.get_events(auth_event_ids)
        if batched_auth_events:
            auth_events_by_id.update(batched_auth_events)
        check_state_dependent_auth_rules(event, auth_events_by_id.values())

    def compute_auth_events(
        self,
        event: Union[EventBase, EventBuilder],
        current_state_ids: StateMap[str],
        for_verification: bool = False,
    ) -> List[str]:
        """Given an event and current state return the list of event IDs used
        to auth an event.

        If `for_verification` is False then only return auth events that
        should be added to the event's `auth_events`.

        Returns:
            List of event IDs.
        """

        if event.type == EventTypes.Create:
            return []

        # Currently we ignore the `for_verification` flag even though there are
        # some situations where we can drop particular auth events when adding
        # to the event's `auth_events` (e.g. joins pointing to previous joins
        # when room is publicly joinable). Dropping event IDs has the
        # advantage that the auth chain for the room grows slower, but we use
        # the auth chain in state resolution v2 to order events, which means
        # care must be taken if dropping events to ensure that it doesn't
        # introduce undesirable "state reset" behaviour.
        #
        # All of which sounds a bit tricky so we don't bother for now.
        auth_ids = []
        for etype, state_key in event_auth.auth_types_for_event(
            event.room_version, event
        ):
            auth_ev_id = current_state_ids.get((etype, state_key))
            if auth_ev_id:
                auth_ids.append(auth_ev_id)

        return auth_ids

    async def get_user_which_could_invite(
        self, room_id: str, current_state_ids: StateMap[str]
    ) -> str:
        """
        Searches the room state for a local user who has the power level necessary
        to invite other users.

        Args:
            room_id: The room ID under search.
            current_state_ids: The current state of the room.

        Returns:
            The MXID of the user which could issue an invite.

        Raises:
            SynapseError if no appropriate user is found.
        """
        power_level_event_id = current_state_ids.get((EventTypes.PowerLevels, ""))
        invite_level = 0
        users_default_level = 0
        if power_level_event_id:
            power_level_event = await self._store.get_event(power_level_event_id)
            invite_level = power_level_event.content.get("invite", invite_level)
            users_default_level = power_level_event.content.get(
                "users_default", users_default_level
            )
            users = power_level_event.content.get("users", {})
        else:
            users = {}

        # Find the user with the highest power level (only interested in local
        # users).
        local_users_in_room = await self._store.get_local_users_in_room(room_id)
        chosen_user = max(
            local_users_in_room,
            key=lambda user: users.get(user, users_default_level),
            default=None,
        )

        # Return the chosen if they can issue invites.
        user_power_level = users.get(chosen_user, users_default_level)
        if chosen_user and user_power_level >= invite_level:
            logger.debug(
                "Found a user who can issue invites  %s with power level %d >= invite level %d",
                chosen_user,
                user_power_level,
                invite_level,
            )
            return chosen_user

        # No user was found.
        raise SynapseError(
            400,
            "Unable to find a user which could issue an invite",
            Codes.UNABLE_TO_GRANT_JOIN,
        )

    async def is_host_in_room(self, room_id: str, host: str) -> bool:
        return await self._store.is_host_joined(room_id, host)

    async def assert_host_in_room(
        self, room_id: str, host: str, allow_partial_state_rooms: bool = False
    ) -> None:
        """
        Asserts that the host is in the room, or raises an AuthError.

        If the room is partial-stated, we raise an AuthError with the
        UNABLE_DUE_TO_PARTIAL_STATE error code, unless `allow_partial_state_rooms` is true.

        If allow_partial_state_rooms is True and the room is partial-stated,
        this function may return an incorrect result as we are not able to fully
        track server membership in a room without full state.
        """
        if not allow_partial_state_rooms and await self._store.is_partial_state_room(
            room_id
        ):
            raise AuthError(
                403,
                "Unable to authorise you right now; room is partial-stated here.",
                errcode=Codes.UNABLE_DUE_TO_PARTIAL_STATE,
            )

        if not await self.is_host_in_room(room_id, host):
            raise AuthError(403, "Host not in room.")

    async def check_restricted_join_rules(
        self,
        state_ids: StateMap[str],
        room_version: RoomVersion,
        user_id: str,
        prev_member_event: Optional[EventBase],
    ) -> None:
        """
        Check whether a user can join a room without an invite due to restricted join rules.

        When joining a room with restricted joined rules (as defined in MSC3083),
        the membership of rooms must be checked during a room join.

        Args:
            state_ids: The state of the room as it currently is.
            room_version: The room version of the room being joined.
            user_id: The user joining the room.
            prev_member_event: The current membership event for this user.

        Raises:
            AuthError if the user cannot join the room.
        """
        # If the member is invited or currently joined, then nothing to do.
        if prev_member_event and (
            prev_member_event.membership in (Membership.JOIN, Membership.INVITE)
        ):
            return

        # This is not a room with a restricted join rule, so we don't need to do the
        # restricted room specific checks.
        #
        # Note: We'll be applying the standard join rule checks later, which will
        # catch the cases of e.g. trying to join private rooms without an invite.
        if not await self.has_restricted_join_rules(state_ids, room_version):
            return

        # Get the rooms which allow access to this room and check if the user is
        # in any of them.
        allowed_rooms = await self.get_rooms_that_allow_join(state_ids)
        if not await self.is_user_in_rooms(allowed_rooms, user_id):

            # If this is a remote request, the user might be in an allowed room
            # that we do not know about.
            if get_domain_from_id(user_id) != self._server_name:
                for room_id in allowed_rooms:
                    if not await self._store.is_host_joined(room_id, self._server_name):
                        raise SynapseError(
                            400,
                            f"Unable to check if {user_id} is in allowed rooms.",
                            Codes.UNABLE_AUTHORISE_JOIN,
                        )

            raise AuthError(
                403,
                "You do not belong to any of the required rooms/spaces to join this room.",
            )

    async def has_restricted_join_rules(
        self, state_ids: StateMap[str], room_version: RoomVersion
    ) -> bool:
        """
        Return if the room has the proper join rules set for access via rooms.

        Args:
            state_ids: The state of the room as it currently is.
            room_version: The room version of the room to query.

        Returns:
            True if the proper room version and join rules are set for restricted access.
        """
        # This only applies to room versions which support the new join rule.
        if not room_version.msc3083_join_rules:
            return False

        # If there's no join rule, then it defaults to invite (so this doesn't apply).
        join_rules_event_id = state_ids.get((EventTypes.JoinRules, ""), None)
        if not join_rules_event_id:
            return False

        # If the join rule is not restricted, this doesn't apply.
        join_rules_event = await self._store.get_event(join_rules_event_id)
        content_join_rule = join_rules_event.content.get("join_rule")
        if content_join_rule == JoinRules.RESTRICTED:
            return True

        # also check for MSC3787 behaviour
        if room_version.msc3787_knock_restricted_join_rule:
            return content_join_rule == JoinRules.KNOCK_RESTRICTED

        return False

    async def get_rooms_that_allow_join(
        self, state_ids: StateMap[str]
    ) -> Collection[str]:
        """
        Generate a list of rooms in which membership allows access to a room.

        Args:
            state_ids: The current state of the room the user wishes to join

        Returns:
            A collection of room IDs. Membership in any of the rooms in the list grants the ability to join the target room.
        """
        # If there's no join rule, then it defaults to invite (so this doesn't apply).
        join_rules_event_id = state_ids.get((EventTypes.JoinRules, ""), None)
        if not join_rules_event_id:
            return ()

        # If the join rule is not restricted, this doesn't apply.
        join_rules_event = await self._store.get_event(join_rules_event_id)

        # If allowed is of the wrong form, then only allow invited users.
        allow_list = join_rules_event.content.get("allow", [])
        if not isinstance(allow_list, list):
            return ()

        # Pull out the other room IDs, invalid data gets filtered.
        result = []
        for allow in allow_list:
            if not isinstance(allow, dict):
                continue

            # If the type is unexpected, skip it.
            if allow.get("type") != RestrictedJoinRuleTypes.ROOM_MEMBERSHIP:
                continue

            room_id = allow.get("room_id")
            if not isinstance(room_id, str):
                continue

            result.append(room_id)

        return result

    async def is_user_in_rooms(self, room_ids: Collection[str], user_id: str) -> bool:
        """
        Check whether a user is a member of any of the provided rooms.

        Args:
            room_ids: The rooms to check for membership.
            user_id: The user to check.

        Returns:
            True if the user is in any of the rooms, false otherwise.
        """
        if not room_ids:
            return False

        # Get the list of joined rooms and see if there's an overlap.
        joined_rooms = await self._store.get_rooms_for_user(user_id)

        # Check each room and see if the user is in it.
        for room_id in room_ids:
            if room_id in joined_rooms:
                return True

        # The user was not in any of the rooms.
        return False
