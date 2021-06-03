# Copyright 2017 Vector Creations Ltd
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
from typing import TYPE_CHECKING, Any, Dict, List, Optional

import synapse.metrics
from synapse.api.constants import EventTypes, HistoryVisibility, JoinRules, Membership
from synapse.handlers.state_deltas import StateDeltasHandler
from synapse.metrics.background_process_metrics import run_as_background_process
from synapse.storage.roommember import ProfileInfo
from synapse.types import JsonDict
from synapse.util.metrics import Measure

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


class UserDirectoryHandler(StateDeltasHandler):
    """Handles querying of and keeping updated the user_directory.

    N.B.: ASSUMES IT IS THE ONLY THING THAT MODIFIES THE USER DIRECTORY

    The user directory is filled with users who this server can see are joined to a
    world_readable or publicly joinable room. We keep a database table up to date
    by streaming changes of the current state and recalculating whether users should
    be in the directory or not when necessary.
    """

    def __init__(self, hs: "HomeServer"):
        super().__init__(hs)

        self.store = hs.get_datastore()
        self.server_name = hs.hostname
        self.clock = hs.get_clock()
        self.notifier = hs.get_notifier()
        self.is_mine_id = hs.is_mine_id
        self.update_user_directory = hs.config.update_user_directory
        self.search_all_users = hs.config.user_directory_search_all_users
        self.spam_checker = hs.get_spam_checker()
        # The current position in the current_state_delta stream
        self.pos = None  # type: Optional[int]

        # Guard to ensure we only process deltas one at a time
        self._is_processing = False

        if self.update_user_directory:
            self.notifier.add_replication_callback(self.notify_new_event)

            # We kick this off so that we don't have to wait for a change before
            # we start populating the user directory
            self.clock.call_later(0, self.notify_new_event)

    async def search_users(
        self, user_id: str, search_term: str, limit: int
    ) -> JsonDict:
        """Searches for users in directory

        Returns:
            dict of the form::

                {
                    "limited": <bool>,  # whether there were more results or not
                    "results": [  # Ordered by best match first
                        {
                            "user_id": <user_id>,
                            "display_name": <display_name>,
                            "avatar_url": <avatar_url>
                        }
                    ]
                }
        """
        results = await self.store.search_user_dir(user_id, search_term, limit)

        # Remove any spammy users from the results.
        non_spammy_users = []
        for user in results["results"]:
            if not await self.spam_checker.check_username_for_spam(user):
                non_spammy_users.append(user)
        results["results"] = non_spammy_users

        return results

    def notify_new_event(self) -> None:
        """Called when there may be more deltas to process"""
        if not self.update_user_directory:
            return

        if self._is_processing:
            return

        async def process():
            try:
                await self._unsafe_process()
            finally:
                self._is_processing = False

        self._is_processing = True
        run_as_background_process("user_directory.notify_new_event", process)

    async def handle_local_profile_change(
        self, user_id: str, profile: ProfileInfo
    ) -> None:
        """Called to update index of our local user profiles when they change
        irrespective of any rooms the user may be in.
        """
        # FIXME(#3714): We should probably do this in the same worker as all
        # the other changes.

        # Support users are for diagnostics and should not appear in the user directory.
        is_support = await self.store.is_support_user(user_id)
        # When change profile information of deactivated user it should not appear in the user directory.
        is_deactivated = await self.store.get_user_deactivated_status(user_id)

        if not (is_support or is_deactivated):
            await self.store.update_profile_in_user_dir(
                user_id, profile.display_name, profile.avatar_url
            )

    async def handle_user_deactivated(self, user_id: str) -> None:
        """Called when a user ID is deactivated"""
        # FIXME(#3714): We should probably do this in the same worker as all
        # the other changes.
        await self.store.remove_from_user_dir(user_id)

    async def _unsafe_process(self) -> None:
        # If self.pos is None then means we haven't fetched it from DB
        if self.pos is None:
            self.pos = await self.store.get_user_directory_stream_pos()

        # If still None then the initial background update hasn't happened yet.
        if self.pos is None:
            return None

        # Loop round handling deltas until we're up to date
        while True:
            with Measure(self.clock, "user_dir_delta"):
                room_max_stream_ordering = self.store.get_room_max_stream_ordering()
                if self.pos == room_max_stream_ordering:
                    return

                logger.debug(
                    "Processing user stats %s->%s", self.pos, room_max_stream_ordering
                )
                max_pos, deltas = await self.store.get_current_state_deltas(
                    self.pos, room_max_stream_ordering
                )

                logger.debug("Handling %d state deltas", len(deltas))
                await self._handle_deltas(deltas)

                self.pos = max_pos

                # Expose current event processing position to prometheus
                synapse.metrics.event_processing_positions.labels("user_dir").set(
                    max_pos
                )

                await self.store.update_user_directory_stream_pos(max_pos)

    async def _handle_deltas(self, deltas: List[Dict[str, Any]]) -> None:
        """Called with the state deltas to process"""
        for delta in deltas:
            typ = delta["type"]
            state_key = delta["state_key"]
            room_id = delta["room_id"]
            event_id = delta["event_id"]
            prev_event_id = delta["prev_event_id"]

            logger.debug("Handling: %r %r, %s", typ, state_key, event_id)

            # For join rule and visibility changes we need to check if the room
            # may have become public or not and add/remove the users in said room
            if typ in (EventTypes.RoomHistoryVisibility, EventTypes.JoinRules):
                await self._handle_room_publicity_change(
                    room_id, prev_event_id, event_id, typ
                )
            elif typ == EventTypes.Member:
                change = await self._get_key_change(
                    prev_event_id,
                    event_id,
                    key_name="membership",
                    public_value=Membership.JOIN,
                )

                if change is False:
                    # Need to check if the server left the room entirely, if so
                    # we might need to remove all the users in that room
                    is_in_room = await self.store.is_host_joined(
                        room_id, self.server_name
                    )
                    if not is_in_room:
                        logger.debug("Server left room: %r", room_id)
                        # Fetch all the users that we marked as being in user
                        # directory due to being in the room and then check if
                        # need to remove those users or not
                        user_ids = await self.store.get_users_in_dir_due_to_room(
                            room_id
                        )

                        for user_id in user_ids:
                            await self._handle_remove_user(room_id, user_id)
                        return
                    else:
                        logger.debug("Server is still in room: %r", room_id)

                is_support = await self.store.is_support_user(state_key)
                if not is_support:
                    if change is None:
                        # Handle any profile changes
                        await self._handle_profile_change(
                            state_key, room_id, prev_event_id, event_id
                        )
                        continue

                    if change:  # The user joined
                        event = await self.store.get_event(event_id, allow_none=True)
                        # It isn't expected for this event to not exist, but we
                        # don't want the entire background process to break.
                        if event is None:
                            continue

                        profile = ProfileInfo(
                            avatar_url=event.content.get("avatar_url"),
                            display_name=event.content.get("displayname"),
                        )

                        await self._handle_new_user(room_id, state_key, profile)
                    else:  # The user left
                        await self._handle_remove_user(room_id, state_key)
            else:
                logger.debug("Ignoring irrelevant type: %r", typ)

    async def _handle_room_publicity_change(
        self,
        room_id: str,
        prev_event_id: Optional[str],
        event_id: Optional[str],
        typ: str,
    ) -> None:
        """Handle a room having potentially changed from/to world_readable/publicly
        joinable.

        Args:
            room_id: The ID of the room which changed.
            prev_event_id: The previous event before the state change
            event_id: The new event after the state change
            typ: Type of the event
        """
        logger.debug("Handling change for %s: %s", typ, room_id)

        if typ == EventTypes.RoomHistoryVisibility:
            change = await self._get_key_change(
                prev_event_id,
                event_id,
                key_name="history_visibility",
                public_value=HistoryVisibility.WORLD_READABLE,
            )
        elif typ == EventTypes.JoinRules:
            change = await self._get_key_change(
                prev_event_id,
                event_id,
                key_name="join_rule",
                public_value=JoinRules.PUBLIC,
            )
        else:
            raise Exception("Invalid event type")
        # If change is None, no change. True => become world_readable/public,
        # False => was world_readable/public
        if change is None:
            logger.debug("No change")
            return

        # There's been a change to or from being world readable.

        is_public = await self.store.is_room_world_readable_or_publicly_joinable(
            room_id
        )

        logger.debug("Change: %r, is_public: %r", change, is_public)

        if change and not is_public:
            # If we became world readable but room isn't currently public then
            # we ignore the change
            return
        elif not change and is_public:
            # If we stopped being world readable but are still public,
            # ignore the change
            return

        other_users_in_room_with_profiles = (
            await self.store.get_users_in_room_with_profiles(room_id)
        )

        # Remove every user from the sharing tables for that room.
        for user_id in other_users_in_room_with_profiles.keys():
            await self.store.remove_user_who_share_room(user_id, room_id)

        # Then, re-add them to the tables.
        # NOTE: this is not the most efficient method, as handle_new_user sets
        # up local_user -> other_user and other_user_whos_local -> local_user,
        # which when ran over an entire room, will result in the same values
        # being added multiple times. The batching upserts shouldn't make this
        # too bad, though.
        for user_id, profile in other_users_in_room_with_profiles.items():
            await self._handle_new_user(room_id, user_id, profile)

    async def _handle_new_user(
        self, room_id: str, user_id: str, profile: ProfileInfo
    ) -> None:
        """Called when we might need to add user to directory

        Args:
            room_id: The room ID that user joined or started being public
            user_id
        """
        logger.debug("Adding new user to dir, %r", user_id)

        await self.store.update_profile_in_user_dir(
            user_id, profile.display_name, profile.avatar_url
        )

        is_public = await self.store.is_room_world_readable_or_publicly_joinable(
            room_id
        )
        # Now we update users who share rooms with users.
        other_users_in_room = await self.store.get_users_in_room(room_id)

        if is_public:
            await self.store.add_users_in_public_rooms(room_id, (user_id,))
        else:
            to_insert = set()

            # First, if they're our user then we need to update for every user
            if self.is_mine_id(user_id):

                is_appservice = self.store.get_if_app_services_interested_in_user(
                    user_id
                )

                # We don't care about appservice users.
                if not is_appservice:
                    for other_user_id in other_users_in_room:
                        if user_id == other_user_id:
                            continue

                        to_insert.add((user_id, other_user_id))

            # Next we need to update for every local user in the room
            for other_user_id in other_users_in_room:
                if user_id == other_user_id:
                    continue

                is_appservice = self.store.get_if_app_services_interested_in_user(
                    other_user_id
                )
                if self.is_mine_id(other_user_id) and not is_appservice:
                    to_insert.add((other_user_id, user_id))

            if to_insert:
                await self.store.add_users_who_share_private_room(room_id, to_insert)

    async def _handle_remove_user(self, room_id: str, user_id: str) -> None:
        """Called when we might need to remove user from directory

        Args:
            room_id: The room ID that user left or stopped being public that
            user_id
        """
        logger.debug("Removing user %r", user_id)

        # Remove user from sharing tables
        await self.store.remove_user_who_share_room(user_id, room_id)

        # Are they still in any rooms? If not, remove them entirely.
        rooms_user_is_in = await self.store.get_user_dir_rooms_user_is_in(user_id)

        if len(rooms_user_is_in) == 0:
            await self.store.remove_from_user_dir(user_id)

    async def _handle_profile_change(
        self,
        user_id: str,
        room_id: str,
        prev_event_id: Optional[str],
        event_id: Optional[str],
    ) -> None:
        """Check member event changes for any profile changes and update the
        database if there are.
        """
        if not prev_event_id or not event_id:
            return

        prev_event = await self.store.get_event(prev_event_id, allow_none=True)
        event = await self.store.get_event(event_id, allow_none=True)

        if not prev_event or not event:
            return

        if event.membership != Membership.JOIN:
            return

        prev_name = prev_event.content.get("displayname")
        new_name = event.content.get("displayname")
        # If the new name is an unexpected form, do not update the directory.
        if not isinstance(new_name, str):
            new_name = prev_name

        prev_avatar = prev_event.content.get("avatar_url")
        new_avatar = event.content.get("avatar_url")
        # If the new avatar is an unexpected form, do not update the directory.
        if not isinstance(new_avatar, str):
            new_avatar = prev_avatar

        if prev_name != new_name or prev_avatar != new_avatar:
            await self.store.update_profile_in_user_dir(user_id, new_name, new_avatar)
