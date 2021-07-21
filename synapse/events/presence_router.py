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

    ALL_USERS = "ALL"

    def __init__(self, hs: "HomeServer"):
        self.custom_presence_router = None

        # Check whether a custom presence router module has been configured
        if hs.config.presence_router_module_class:
            # Initialise the module
            self.custom_presence_router = hs.config.presence_router_module_class(
                config=hs.config.presence_router_config, module_api=hs.get_module_api()
            )

            # Ensure the module has implemented the required methods
            required_methods = ["get_users_for_states", "get_interested_users"]
            for method_name in required_methods:
                if not hasattr(self.custom_presence_router, method_name):
                    raise Exception(
                        "PresenceRouter module '%s' must implement all required methods: %s"
                        % (
                            hs.config.presence_router_module_class.__name__,
                            ", ".join(required_methods),
                        )
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
        if self.custom_presence_router is not None:
            # Ask the custom module
            return await self.custom_presence_router.get_users_for_states(
                state_updates=state_updates
            )

        # Don't include any extra destinations for presence updates
        return {}

    async def get_interested_users(self, user_id: str) -> Union[Set[str], ALL_USERS]:
        """
        Retrieve a list of users that `user_id` is interested in receiving the
        presence of. This will be in addition to those they share a room with.
        Optionally, the object PresenceRouter.ALL_USERS can be returned to indicate
        that this user should receive all incoming local and remote presence updates.

        Note that this method will only be called for local users, but can return users
        that are local or remote.

        Args:
            user_id: A user requesting presence updates.

        Returns:
            A set of user IDs to return presence updates for, or ALL_USERS to return all
            known updates.
        """
        if self.custom_presence_router is not None:
            # Ask the custom module for interested users
            return await self.custom_presence_router.get_interested_users(
                user_id=user_id
            )

        # A custom presence router is not defined.
        # Don't report any additional interested users
        return set()
