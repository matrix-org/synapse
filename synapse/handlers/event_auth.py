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
from typing import TYPE_CHECKING, Optional

from synapse.api.constants import EventTypes, JoinRules, Membership
from synapse.api.errors import AuthError
from synapse.api.room_versions import RoomVersion
from synapse.events import EventBase
from synapse.types import StateMap

if TYPE_CHECKING:
    from synapse.server import HomeServer


class EventAuthHandler:
    """
    This class contains methods for authenticating events added to room graphs.
    """

    def __init__(self, hs: "HomeServer"):
        self._store = hs.get_datastore()

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
        the membership of spaces must be checked during a room join.

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

        # This only applies to room versions which support the new join rule.
        if not room_version.msc3083_join_rules:
            return

        # If there's no join rule, then it defaults to invite (so this doesn't apply).
        join_rules_event_id = state_ids.get((EventTypes.JoinRules, ""), None)
        if not join_rules_event_id:
            return

        # If the join rule is not restricted, this doesn't apply.
        join_rules_event = await self._store.get_event(join_rules_event_id)
        if join_rules_event.content.get("join_rule") != JoinRules.MSC3083_RESTRICTED:
            return

        # If allowed is of the wrong form, then only allow invited users.
        allowed_spaces = join_rules_event.content.get("allow", [])
        if not isinstance(allowed_spaces, list):
            allowed_spaces = ()

        # Get the list of joined rooms and see if there's an overlap.
        if allowed_spaces:
            joined_rooms = await self._store.get_rooms_for_user(user_id)
        else:
            joined_rooms = ()

        # Pull out the other room IDs, invalid data gets filtered.
        for space in allowed_spaces:
            if not isinstance(space, dict):
                continue

            space_id = space.get("space")
            if not isinstance(space_id, str):
                continue

            # The user was joined to one of the spaces specified, they can join
            # this room!
            if space_id in joined_rooms:
                return

        # The user was not in any of the required spaces.
        raise AuthError(
            403,
            "You do not belong to any of the required spaces to join this room.",
        )
