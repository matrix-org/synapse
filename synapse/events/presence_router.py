# -*- coding: utf-8 -*-
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

from typing import TYPE_CHECKING, Dict, Iterable, Set, Union

from synapse.api.presence import UserPresenceState

if TYPE_CHECKING:
    from synapse.server import HomeServer


class PresenceRouter:
    """
    A module that the homeserver will call upon to help route user presence updates to
    additional destinations. If a custom presence router is configured, calls will be
    passed to that instead.
    """

    def __init__(self, hs: "HomeServer"):
        self.custom_presence_router = None

        # Check whether a custom presence router module has been configured
        if hs.config.presence_router_module_class:
            # Initialise the module
            self.custom_presence_router = hs.config.presence_router_module_class(
                config=hs.config.presence_router_config, module_api=hs.get_module_api()
            )

    async def get_users_for_states(
        self,
        state_updates: Iterable[UserPresenceState],
    ) -> Dict[str, Set[UserPresenceState]]:
        """
        Given an iterable of user presence updates, determine where each one
        needs to go.

        Args:
            state_updates: An iterable of user presence state updates.

        Returns:
          A dictionary of user_id -> set of UserPresenceState, indicating which
          presence updates each user should receive.
        """
        if self.custom_presence_router is not None and hasattr(
            self.custom_presence_router, "get_users_for_states"
        ):
            # Ask the custom module
            return await self.custom_presence_router.get_users_for_states(
                state_updates=state_updates
            )

        # Don't include any extra destinations for presence updates
        return {}

    async def get_interested_users(self, user_id: str) -> Union[Set[str], str]:
        """
        Retrieve a list of users that the provided user is interested in receiving the presence
        of. Optionally, the str "ALL" can be returned to mean that this user should receive all
        local and remote incoming presence.

        Note that this method will only be called for local users.

        Args:
            user_id: A user requesting presence updates.

        Returns:
            A set of user IDs to return presence updates for, or "ALL" to return all
            known updates.
        """
        if self.custom_presence_router is not None and hasattr(
            self.custom_presence_router, "get_interested_users"
        ):
            # Ask the custom module for interested users
            return await self.custom_presence_router.get_interested_users(
                user_id=user_id
            )

        # A custom presence router is not defined, or doesn't implement any relevant function.
        # Don't report any additional interested users.
        return set()
