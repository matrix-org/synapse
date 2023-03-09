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
from typing import TYPE_CHECKING, Dict, Iterable, Set, Union

from twisted.internet.defer import CancelledError

from synapse.api.presence import UserPresenceState
from synapse.util.async_helpers import delay_cancellation

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


class PresenceRouter:
    """
    A module that the homeserver will call upon to help route user presence updates to
    additional destinations.
    """

    ALL_USERS = "ALL"

    def __init__(self, hs: "HomeServer"):
        self._module_api_callbacks = hs.get_module_api_callbacks().presence_router

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

        # Bail out early if we don't have any callbacks to run.
        if len(self._module_api_callbacks.get_users_for_states_callbacks) == 0:
            # Don't include any extra destinations for presence updates
            return {}

        users_for_states: Dict[str, Set[UserPresenceState]] = {}
        # run all the callbacks for get_users_for_states and combine the results
        for callback in self._module_api_callbacks.get_users_for_states_callbacks:
            try:
                # Note: result is an object here, because we don't trust modules to
                # return the types they're supposed to.
                result: object = await delay_cancellation(callback(state_updates))
            except CancelledError:
                raise
            except Exception as e:
                logger.warning("Failed to run module API callback %s: %s", callback, e)
                continue

            if not isinstance(result, Dict):
                logger.warning(
                    "Wrong type returned by module API callback %s: %s, expected Dict",
                    callback,
                    result,
                )
                continue

            for key, new_entries in result.items():
                if not isinstance(new_entries, Set):
                    logger.warning(
                        "Wrong type returned by module API callback %s: %s, expected Set",
                        callback,
                        new_entries,
                    )
                    break
                users_for_states.setdefault(key, set()).update(new_entries)

        return users_for_states

    async def get_interested_users(self, user_id: str) -> Union[Set[str], str]:
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

        # Bail out early if we don't have any callbacks to run.
        if len(self._module_api_callbacks.get_interested_users_callbacks) == 0:
            # Don't report any additional interested users
            return set()

        interested_users = set()
        # run all the callbacks for get_interested_users and combine the results
        for callback in self._module_api_callbacks.get_interested_users_callbacks:
            try:
                result = await delay_cancellation(callback(user_id))
            except CancelledError:
                raise
            except Exception as e:
                logger.warning("Failed to run module API callback %s: %s", callback, e)
                continue

            # If one of the callbacks returns ALL_USERS then we can stop calling all
            # of the other callbacks, since the set of interested_users is already as
            # large as it can possibly be
            if result == PresenceRouter.ALL_USERS:
                return PresenceRouter.ALL_USERS

            if not isinstance(result, Set):
                logger.warning(
                    "Wrong type returned by module API callback %s: %s, expected set",
                    callback,
                    result,
                )
                continue

            # Add the new interested users to the set
            interested_users.update(result)

        return interested_users
