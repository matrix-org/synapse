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
from http import HTTPStatus
from typing import TYPE_CHECKING, List, Optional, Set, Tuple

from twisted.internet.interfaces import IDelayedCall

import synapse.metrics
from synapse.api.constants import EventTypes, HistoryVisibility, JoinRules, Membership
from synapse.api.errors import Codes, SynapseError
from synapse.handlers.state_deltas import MatchChange, StateDeltasHandler
from synapse.metrics.background_process_metrics import run_as_background_process
from synapse.storage.databases.main.state_deltas import StateDelta
from synapse.storage.databases.main.user_directory import SearchResult
from synapse.storage.roommember import ProfileInfo
from synapse.types import UserID
from synapse.util.metrics import Measure
from synapse.util.retryutils import NotRetryingDestination
from synapse.util.stringutils import non_null_str_or_none

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)

# Don't refresh a stale user directory entry, using a Federation /profile request,
# for 60 seconds. This gives time for other state events to arrive (which will
# then be coalesced such that only one /profile request is made).
USER_DIRECTORY_STALE_REFRESH_TIME_MS = 60 * 1000

# Maximum number of remote servers that we will attempt to refresh profiles for
# in one go.
MAX_SERVERS_TO_REFRESH_PROFILES_FOR_IN_ONE_GO = 5

# As long as we have servers to refresh (without backoff), keep adding more
# every 15 seconds.
INTERVAL_TO_ADD_MORE_SERVERS_TO_REFRESH_PROFILES = 15


def calculate_time_of_next_retry(now_ts: int, retry_count: int) -> int:
    """
    Calculates the time of a next retry given `now_ts` in ms and the number
    of failures encountered thus far.

    Currently the sequence goes:
    1 min, 5 min, 25 min, 2 hour, 10 hour, 52 hour, 10 day, 7.75 week
    """
    return now_ts + 60_000 * (5 ** min(retry_count, 7))


class UserDirectoryHandler(StateDeltasHandler):
    """Handles queries and updates for the user_directory.

    N.B.: ASSUMES IT IS THE ONLY THING THAT MODIFIES THE USER DIRECTORY

    When a local user searches the user_directory, we report two kinds of users:

    - users this server can see are joined to a world_readable or publicly
      joinable room, and
    - users belonging to a private room shared by that local user.

    The two cases are tracked separately in the `users_in_public_rooms` and
    `users_who_share_private_rooms` tables. Both kinds of users have their
    username and avatar tracked in a `user_directory` table.

    This handler has three responsibilities:
    1. Forwarding requests to `/user_directory/search` to the UserDirectoryStore.
    2. Providing hooks for the application to call when local users are added,
       removed, or have their profile changed.
    3. Listening for room state changes that indicate remote users have
       joined or left a room, or that their profile has changed.
    """

    def __init__(self, hs: "HomeServer"):
        super().__init__(hs)

        self.store = hs.get_datastores().main
        self._storage_controllers = hs.get_storage_controllers()
        self.server_name = hs.hostname
        self.clock = hs.get_clock()
        self.notifier = hs.get_notifier()
        self.is_mine_id = hs.is_mine_id
        self.update_user_directory = hs.config.worker.should_update_user_directory
        self.search_all_users = hs.config.userdirectory.user_directory_search_all_users
        self.show_locked_users = hs.config.userdirectory.show_locked_users
        self._spam_checker_module_callbacks = hs.get_module_api_callbacks().spam_checker
        self._hs = hs

        # The current position in the current_state_delta stream
        self.pos: Optional[int] = None

        # Guard to ensure we only process deltas one at a time
        self._is_processing = False

        # Guard to ensure we only have one process for refreshing remote profiles
        self._is_refreshing_remote_profiles = False
        # Handle to cancel the `call_later` of `kick_off_remote_profile_refresh_process`
        self._refresh_remote_profiles_call_later: Optional[IDelayedCall] = None

        # Guard to ensure we only have one process for refreshing remote profiles
        # for the given servers.
        # Set of server names.
        self._is_refreshing_remote_profiles_for_servers: Set[str] = set()

        if self.update_user_directory:
            self.notifier.add_replication_callback(self.notify_new_event)

            # We kick this off so that we don't have to wait for a change before
            # we start populating the user directory
            self.clock.call_later(0, self.notify_new_event)

            # Kick off the profile refresh process on startup
            self._refresh_remote_profiles_call_later = self.clock.call_later(
                10, self.kick_off_remote_profile_refresh_process
            )

    async def search_users(
        self, user_id: str, search_term: str, limit: int
    ) -> SearchResult:
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
        results = await self.store.search_user_dir(
            user_id, search_term, limit, self.show_locked_users
        )

        # Remove any spammy users from the results.
        non_spammy_users = []
        for user in results["results"]:
            if not await self._spam_checker_module_callbacks.check_username_for_spam(
                user
            ):
                non_spammy_users.append(user)
        results["results"] = non_spammy_users

        return results

    def notify_new_event(self) -> None:
        """Called when there may be more deltas to process"""
        if not self.update_user_directory:
            return

        if self._is_processing:
            return

        async def process() -> None:
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
        # FIXME(https://github.com/matrix-org/synapse/issues/3714): We should
        # probably do this in the same worker as all the other changes.

        if await self.store.should_include_local_user_in_dir(user_id):
            await self.store.update_profile_in_user_dir(
                user_id, profile.display_name, profile.avatar_url
            )

    async def handle_local_user_deactivated(self, user_id: str) -> None:
        """Called when a user ID is deactivated"""
        # FIXME(https://github.com/matrix-org/synapse/issues/3714): We should
        # probably do this in the same worker as all the other changes.
        await self.store.remove_from_user_dir(user_id)

    async def _unsafe_process(self) -> None:
        # If self.pos is None then means we haven't fetched it from DB
        if self.pos is None:
            self.pos = await self.store.get_user_directory_stream_pos()

            # If still None then the initial background update hasn't happened yet.
            if self.pos is None:
                return None

            room_max_stream_ordering = self.store.get_room_max_stream_ordering()
            if self.pos > room_max_stream_ordering:
                # apparently, we've processed more events than exist in the database!
                # this can happen if events are removed with history purge or similar.
                logger.warning(
                    "Event stream ordering appears to have gone backwards (%i -> %i): "
                    "rewinding user directory processor",
                    self.pos,
                    room_max_stream_ordering,
                )
                self.pos = room_max_stream_ordering

        # Loop round handling deltas until we're up to date
        while True:
            with Measure(self.clock, "user_dir_delta"):
                room_max_stream_ordering = self.store.get_room_max_stream_ordering()
                if self.pos == room_max_stream_ordering:
                    return

                logger.debug(
                    "Processing user stats %s->%s", self.pos, room_max_stream_ordering
                )
                (
                    max_pos,
                    deltas,
                ) = await self._storage_controllers.state.get_current_state_deltas(
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

    async def _handle_deltas(self, deltas: List[StateDelta]) -> None:
        """Called with the state deltas to process"""
        for delta in deltas:
            logger.debug(
                "Handling: %r %r, %s", delta.event_type, delta.state_key, delta.event_id
            )

            # For join rule and visibility changes we need to check if the room
            # may have become public or not and add/remove the users in said room
            if delta.event_type in (
                EventTypes.RoomHistoryVisibility,
                EventTypes.JoinRules,
            ):
                await self._handle_room_publicity_change(
                    delta.room_id, delta.prev_event_id, delta.event_id, delta.event_type
                )
            elif delta.event_type == EventTypes.Member:
                await self._handle_room_membership_event(
                    delta.room_id,
                    delta.prev_event_id,
                    delta.event_id,
                    delta.state_key,
                )
            else:
                logger.debug("Ignoring irrelevant type: %r", delta.event_type)

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
            publicness = await self._get_key_change(
                prev_event_id,
                event_id,
                key_name="history_visibility",
                public_value=HistoryVisibility.WORLD_READABLE,
            )
        elif typ == EventTypes.JoinRules:
            publicness = await self._get_key_change(
                prev_event_id,
                event_id,
                key_name="join_rule",
                public_value=JoinRules.PUBLIC,
            )
        else:
            raise Exception("Invalid event type")
        if publicness is MatchChange.no_change:
            logger.debug("No change")
            return

        # There's been a change to or from being world readable.

        is_public = await self.store.is_room_world_readable_or_publicly_joinable(
            room_id
        )

        logger.debug("Publicness change: %r, is_public: %r", publicness, is_public)

        if publicness is MatchChange.now_true and not is_public:
            # If we became world readable but room isn't currently public then
            # we ignore the change
            return
        elif publicness is MatchChange.now_false and is_public:
            # If we stopped being world readable but are still public,
            # ignore the change
            return

        users_in_room = await self.store.get_users_in_room(room_id)

        # Remove every user from the sharing tables for that room.
        for user_id in users_in_room:
            await self.store.remove_user_who_share_room(user_id, room_id)

        # Then, re-add all remote users and some local users to the tables.
        # NOTE: this is not the most efficient method, as _track_user_joined_room sets
        # up local_user -> other_user and other_user_whos_local -> local_user,
        # which when ran over an entire room, will result in the same values
        # being added multiple times. The batching upserts shouldn't make this
        # too bad, though.
        for user_id in users_in_room:
            if not self.is_mine_id(
                user_id
            ) or await self.store.should_include_local_user_in_dir(user_id):
                await self._track_user_joined_room(room_id, user_id)

    async def _handle_room_membership_event(
        self,
        room_id: str,
        prev_event_id: Optional[str],
        event_id: Optional[str],
        state_key: str,
    ) -> None:
        """Process a single room membershp event.

        We have to do two things:

        1. Update the room-sharing tables.
           This applies to remote users and non-excluded local users.
        2. Update the user_directory and user_directory_search tables.
           This applies to remote users only, because we only become aware of
           the (and any profile changes) by listening to these events.
           The rest of the application knows exactly when local users are
           created or their profile changed---it will directly call methods
           on this class.
        """
        joined = await self._get_key_change(
            prev_event_id,
            event_id,
            key_name="membership",
            public_value=Membership.JOIN,
        )

        # Both cases ignore excluded local users, so start by discarding them.
        is_remote = not self.is_mine_id(state_key)
        if not is_remote and not await self.store.should_include_local_user_in_dir(
            state_key
        ):
            return

        if joined is MatchChange.now_false:
            # Need to check if the server left the room entirely, if so
            # we might need to remove all the users in that room
            is_in_room = await self.store.is_host_joined(room_id, self.server_name)
            if not is_in_room:
                logger.debug("Server left room: %r", room_id)
                # Fetch all the users that we marked as being in user
                # directory due to being in the room and then check if
                # need to remove those users or not
                user_ids = await self.store.get_users_in_dir_due_to_room(room_id)

                for user_id in user_ids:
                    await self._handle_remove_user(room_id, user_id)
            else:
                logger.debug("Server is still in room: %r", room_id)
                await self._handle_remove_user(room_id, state_key)
        elif joined is MatchChange.no_change:
            # Handle any profile changes for remote users.
            # (For local users the rest of the application calls
            # `handle_local_profile_change`.)
            # Only process if there is an event_id.
            if is_remote and event_id is not None:
                await self._handle_possible_remote_profile_change(
                    state_key, room_id, prev_event_id, event_id
                )
        elif joined is MatchChange.now_true:  # The user joined
            # This may be the first time we've seen a remote user. If
            # so, ensure we have a directory entry for them. (For local users,
            # the rest of the application calls `handle_local_profile_change`.)
            # Only process if there is an event_id.
            if is_remote and event_id is not None:
                await self._handle_possible_remote_profile_change(
                    state_key, room_id, None, event_id
                )
            await self._track_user_joined_room(room_id, state_key)

    async def _track_user_joined_room(self, room_id: str, joining_user_id: str) -> None:
        """Someone's just joined a room. Update `users_in_public_rooms` or
        `users_who_share_private_rooms` as appropriate.

        The caller is responsible for ensuring that the given user should be
        included in the user directory.
        """
        is_public = await self.store.is_room_world_readable_or_publicly_joinable(
            room_id
        )
        if is_public:
            await self.store.add_users_in_public_rooms(room_id, (joining_user_id,))
        else:
            users_in_room = await self.store.get_users_in_room(room_id)
            other_users_in_room = [
                other
                for other in users_in_room
                if other != joining_user_id
                and (
                    # We can't apply any special rules to remote users so
                    # they're always included
                    not self.is_mine_id(other)
                    # Check the special rules whether the local user should be
                    # included in the user directory
                    or await self.store.should_include_local_user_in_dir(other)
                )
            ]
            updates_to_users_who_share_rooms: Set[Tuple[str, str]] = set()

            # First, if the joining user is our local user then we need an
            # update for every other user in the room.
            if self.is_mine_id(joining_user_id):
                for other_user_id in other_users_in_room:
                    updates_to_users_who_share_rooms.add(
                        (joining_user_id, other_user_id)
                    )

            # Next, we need an update for every other local user in the room
            # that they now share a room with the joining user.
            for other_user_id in other_users_in_room:
                if self.is_mine_id(other_user_id):
                    updates_to_users_who_share_rooms.add(
                        (other_user_id, joining_user_id)
                    )

            if updates_to_users_who_share_rooms:
                await self.store.add_users_who_share_private_room(
                    room_id, updates_to_users_who_share_rooms
                )

    async def _handle_remove_user(self, room_id: str, user_id: str) -> None:
        """Called when when someone leaves a room. The user may be local or remote.

        (If the person who left was the last local user in this room, the server
        is no longer in the room. We call this function to forget that the remaining
        remote users are in the room, even though they haven't left. So the name is
        a little misleading!)

        Args:
            room_id: The room ID that user left or stopped being public that
            user_id
        """
        logger.debug("Removing user %r from room %r", user_id, room_id)

        # Remove user from sharing tables
        await self.store.remove_user_who_share_room(user_id, room_id)

        # Additionally, if they're a remote user and we're no longer joined
        # to any rooms they're in, remove them from the user directory.
        if not self.is_mine_id(user_id):
            rooms_user_is_in = await self.store.get_user_dir_rooms_user_is_in(user_id)

            if len(rooms_user_is_in) == 0:
                logger.debug("Removing user %r from directory", user_id)
                await self.store.remove_from_user_dir(user_id)

    async def _handle_possible_remote_profile_change(
        self,
        user_id: str,
        room_id: str,
        prev_event_id: Optional[str],
        event_id: str,
    ) -> None:
        """Check member event changes for any profile changes and update the
        database if there are. This is intended for remote users only. The caller
        is responsible for checking that the given user is remote.
        """

        if not prev_event_id:
            # If we don't have an older event to fall back on, just fetch the same
            # event itself.
            prev_event_id = event_id

        prev_event = await self.store.get_event(prev_event_id, allow_none=True)
        event = await self.store.get_event(event_id, allow_none=True)

        if not prev_event or not event:
            return

        if event.membership != Membership.JOIN:
            return

        is_public = await self.store.is_room_world_readable_or_publicly_joinable(
            room_id
        )
        if not is_public:
            # Don't collect user profiles from private rooms as they are not guaranteed
            # to be the same as the user's global profile.
            now_ts = self.clock.time_msec()
            await self.store.set_remote_user_profile_in_user_dir_stale(
                user_id,
                next_try_at_ms=now_ts + USER_DIRECTORY_STALE_REFRESH_TIME_MS,
                retry_counter=0,
            )
            # Schedule a wake-up to refresh the user directory for this server.
            # We intentionally wake up this server directly because we don't want
            # other servers ahead of it in the queue to get in the way of updating
            # the profile if the server only just sent us an event.
            self.clock.call_later(
                USER_DIRECTORY_STALE_REFRESH_TIME_MS // 1000 + 1,
                self.kick_off_remote_profile_refresh_process_for_remote_server,
                UserID.from_string(user_id).domain,
            )
            # Schedule a wake-up to handle any backoffs that may occur in the future.
            self.clock.call_later(
                2 * USER_DIRECTORY_STALE_REFRESH_TIME_MS // 1000 + 1,
                self.kick_off_remote_profile_refresh_process,
            )
            return

        prev_name = prev_event.content.get("displayname")
        new_name = event.content.get("displayname")
        # If the new name is an unexpected form, replace with None.
        if not isinstance(new_name, str):
            new_name = None

        prev_avatar = prev_event.content.get("avatar_url")
        new_avatar = event.content.get("avatar_url")
        # If the new avatar is an unexpected form, replace with None.
        if not isinstance(new_avatar, str):
            new_avatar = None

        if (
            prev_name != new_name
            or prev_avatar != new_avatar
            or prev_event_id == event_id
        ):
            # Only update if something has changed, or we didn't have a previous event
            # in the first place.
            await self.store.update_profile_in_user_dir(user_id, new_name, new_avatar)

    def kick_off_remote_profile_refresh_process(self) -> None:
        """Called when there may be remote users with stale profiles to be refreshed"""
        if not self.update_user_directory:
            return

        if self._is_refreshing_remote_profiles:
            return

        if self._refresh_remote_profiles_call_later:
            if self._refresh_remote_profiles_call_later.active():
                self._refresh_remote_profiles_call_later.cancel()
            self._refresh_remote_profiles_call_later = None

        async def process() -> None:
            try:
                await self._unsafe_refresh_remote_profiles()
            finally:
                self._is_refreshing_remote_profiles = False

        self._is_refreshing_remote_profiles = True
        run_as_background_process("user_directory.refresh_remote_profiles", process)

    async def _unsafe_refresh_remote_profiles(self) -> None:
        limit = MAX_SERVERS_TO_REFRESH_PROFILES_FOR_IN_ONE_GO - len(
            self._is_refreshing_remote_profiles_for_servers
        )
        if limit <= 0:
            # nothing to do: already refreshing the maximum number of servers
            # at once.
            # Come back later.
            self._refresh_remote_profiles_call_later = self.clock.call_later(
                INTERVAL_TO_ADD_MORE_SERVERS_TO_REFRESH_PROFILES,
                self.kick_off_remote_profile_refresh_process,
            )
            return

        servers_to_refresh = (
            await self.store.get_remote_servers_with_profiles_to_refresh(
                now_ts=self.clock.time_msec(), limit=limit
            )
        )

        if not servers_to_refresh:
            # Do we have any backing-off servers that we should try again
            # for eventually?
            # By setting `now` is a point in the far future, we can ask for
            # which server/user is next to be refreshed, even though it is
            # not actually refreshable *now*.
            end_of_time = 1 << 62
            backing_off_servers = (
                await self.store.get_remote_servers_with_profiles_to_refresh(
                    now_ts=end_of_time, limit=1
                )
            )
            if backing_off_servers:
                # Find out when the next user is refreshable and schedule a
                # refresh then.
                backing_off_server_name = backing_off_servers[0]
                users = await self.store.get_remote_users_to_refresh_on_server(
                    backing_off_server_name, now_ts=end_of_time, limit=1
                )
                if not users:
                    return
                _, _, next_try_at_ts = users[0]
                self._refresh_remote_profiles_call_later = self.clock.call_later(
                    ((next_try_at_ts - self.clock.time_msec()) // 1000) + 2,
                    self.kick_off_remote_profile_refresh_process,
                )

            return

        for server_to_refresh in servers_to_refresh:
            self.kick_off_remote_profile_refresh_process_for_remote_server(
                server_to_refresh
            )

        self._refresh_remote_profiles_call_later = self.clock.call_later(
            INTERVAL_TO_ADD_MORE_SERVERS_TO_REFRESH_PROFILES,
            self.kick_off_remote_profile_refresh_process,
        )

    def kick_off_remote_profile_refresh_process_for_remote_server(
        self, server_name: str
    ) -> None:
        """Called when there may be remote users with stale profiles to be refreshed
        on the given server."""
        if not self.update_user_directory:
            return

        if server_name in self._is_refreshing_remote_profiles_for_servers:
            return

        async def process() -> None:
            try:
                await self._unsafe_refresh_remote_profiles_for_remote_server(
                    server_name
                )
            finally:
                self._is_refreshing_remote_profiles_for_servers.remove(server_name)

        self._is_refreshing_remote_profiles_for_servers.add(server_name)
        run_as_background_process(
            "user_directory.refresh_remote_profiles_for_remote_server", process
        )

    async def _unsafe_refresh_remote_profiles_for_remote_server(
        self, server_name: str
    ) -> None:
        logger.info("Refreshing profiles in user directory for %s", server_name)

        while True:
            # Get a handful of users to process.
            next_batch = await self.store.get_remote_users_to_refresh_on_server(
                server_name, now_ts=self.clock.time_msec(), limit=10
            )
            if not next_batch:
                # Finished for now
                return

            for user_id, retry_counter, _ in next_batch:
                # Request the profile of the user.
                try:
                    profile = await self._hs.get_profile_handler().get_profile(
                        user_id, ignore_backoff=False
                    )
                except NotRetryingDestination as e:
                    logger.info(
                        "Failed to refresh profile for %r because the destination is undergoing backoff",
                        user_id,
                    )
                    # As a special-case, we back off until the destination is no longer
                    # backed off from.
                    await self.store.set_remote_user_profile_in_user_dir_stale(
                        user_id,
                        e.retry_last_ts + e.retry_interval,
                        retry_counter=retry_counter + 1,
                    )
                    continue
                except SynapseError as e:
                    if e.code == HTTPStatus.NOT_FOUND and e.errcode == Codes.NOT_FOUND:
                        # The profile doesn't exist.
                        # TODO Does this mean we should clear it from our user
                        #      directory?
                        await self.store.clear_remote_user_profile_in_user_dir_stale(
                            user_id
                        )
                        logger.warning(
                            "Refresh of remote profile %r: not found (%r)",
                            user_id,
                            e.msg,
                        )
                        continue

                    logger.warning(
                        "Failed to refresh profile for %r because %r", user_id, e
                    )
                    await self.store.set_remote_user_profile_in_user_dir_stale(
                        user_id,
                        calculate_time_of_next_retry(
                            self.clock.time_msec(), retry_counter + 1
                        ),
                        retry_counter=retry_counter + 1,
                    )
                    continue
                except Exception:
                    logger.error(
                        "Failed to refresh profile for %r due to unhandled exception",
                        user_id,
                        exc_info=True,
                    )
                    await self.store.set_remote_user_profile_in_user_dir_stale(
                        user_id,
                        calculate_time_of_next_retry(
                            self.clock.time_msec(), retry_counter + 1
                        ),
                        retry_counter=retry_counter + 1,
                    )
                    continue

                await self.store.update_profile_in_user_dir(
                    user_id,
                    display_name=non_null_str_or_none(profile.get("displayname")),
                    avatar_url=non_null_str_or_none(profile.get("avatar_url")),
                )
