# -*- coding: utf-8 -*-
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

from six import iteritems, iterkeys

from twisted.internet import defer

import synapse.metrics
from synapse.api.constants import EventTypes, JoinRules, Membership
from synapse.handlers.state_deltas import StateDeltasHandler
from synapse.metrics.background_process_metrics import run_as_background_process
from synapse.storage.roommember import ProfileInfo
from synapse.types import get_localpart_from_id
from synapse.util.metrics import Measure

logger = logging.getLogger(__name__)


class UserDirectoryHandler(StateDeltasHandler):
    """Handles querying of and keeping updated the user_directory.

    N.B.: ASSUMES IT IS THE ONLY THING THAT MODIFIES THE USER DIRECTORY

    The user directory is filled with users who this server can see are joined to a
    world_readable or publically joinable room. We keep a database table up to date
    by streaming changes of the current state and recalculating whether users should
    be in the directory or not when necessary.
    """

    def __init__(self, hs):
        super(UserDirectoryHandler, self).__init__(hs)

        self.store = hs.get_datastore()
        self.state = hs.get_state_handler()
        self.server_name = hs.hostname
        self.clock = hs.get_clock()
        self.notifier = hs.get_notifier()
        self.is_mine_id = hs.is_mine_id
        self.update_user_directory = hs.config.update_user_directory
        self.search_all_users = hs.config.user_directory_search_all_users
        # The current position in the current_state_delta stream
        self.pos = None

        # Guard to ensure we only process deltas one at a time
        self._is_processing = False

        if self.update_user_directory:
            self.notifier.add_replication_callback(self.notify_new_event)

            # We kick this off so that we don't have to wait for a change before
            # we start populating the user directory
            self.clock.call_later(0, self.notify_new_event)

    def search_users(self, user_id, search_term, limit):
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
        return self.store.search_user_dir(user_id, search_term, limit)

    def notify_new_event(self):
        """Called when there may be more deltas to process
        """
        if not self.update_user_directory:
            return

        if self._is_processing:
            return

        @defer.inlineCallbacks
        def process():
            try:
                yield self._unsafe_process()
            finally:
                self._is_processing = False

        self._is_processing = True
        run_as_background_process("user_directory.notify_new_event", process)

    @defer.inlineCallbacks
    def handle_local_profile_change(self, user_id, profile):
        """Called to update index of our local user profiles when they change
        irrespective of any rooms the user may be in.
        """
        # FIXME(#3714): We should probably do this in the same worker as all
        # the other changes.
        is_support = yield self.store.is_support_user(user_id)
        # Support users are for diagnostics and should not appear in the user directory.
        if not is_support:
            yield self.store.update_profile_in_user_dir(
                user_id, profile.display_name, profile.avatar_url
            )

    @defer.inlineCallbacks
    def handle_user_deactivated(self, user_id):
        """Called when a user ID is deactivated
        """
        # FIXME(#3714): We should probably do this in the same worker as all
        # the other changes.
        yield self.store.remove_from_user_dir(user_id)

    @defer.inlineCallbacks
    def _unsafe_process(self):
        # If self.pos is None then means we haven't fetched it from DB
        if self.pos is None:
            self.pos = yield self.store.get_user_directory_stream_pos()

        # If still None then the initial background update hasn't happened yet
        if self.pos is None:
            defer.returnValue(None)

        # Loop round handling deltas until we're up to date
        while True:
            with Measure(self.clock, "user_dir_delta"):
                deltas = yield self.store.get_current_state_deltas(self.pos)
                if not deltas:
                    return

                logger.info("Handling %d state deltas", len(deltas))
                yield self._handle_deltas(deltas)

                self.pos = deltas[-1]["stream_id"]

                # Expose current event processing position to prometheus
                synapse.metrics.event_processing_positions.labels("user_dir").set(
                    self.pos
                )

                yield self.store.update_user_directory_stream_pos(self.pos)

    @defer.inlineCallbacks
    def _handle_deltas(self, deltas):
        """Called with the state deltas to process
        """
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
                yield self._handle_room_publicity_change(
                    room_id, prev_event_id, event_id, typ
                )
            elif typ == EventTypes.Member:
                change = yield self._get_key_change(
                    prev_event_id,
                    event_id,
                    key_name="membership",
                    public_value=Membership.JOIN,
                )

                if change is False:
                    # Need to check if the server left the room entirely, if so
                    # we might need to remove all the users in that room
                    is_in_room = yield self.store.is_host_joined(
                        room_id, self.server_name
                    )
                    if not is_in_room:
                        logger.info("Server left room: %r", room_id)
                        # Fetch all the users that we marked as being in user
                        # directory due to being in the room and then check if
                        # need to remove those users or not
                        user_ids = yield self.store.get_users_in_dir_due_to_room(
                            room_id
                        )

                        for user_id in user_ids:
                            yield self._handle_remove_user(room_id, user_id)
                        return
                    else:
                        logger.debug("Server is still in room: %r", room_id)

                is_support = yield self.store.is_support_user(state_key)
                if not is_support:
                    if change is None:
                        # Handle any profile changes
                        yield self._handle_profile_change(
                            state_key, room_id, prev_event_id, event_id
                        )
                        continue

                    if change:  # The user joined
                        event = yield self.store.get_event(event_id, allow_none=True)
                        profile = ProfileInfo(
                            avatar_url=event.content.get("avatar_url"),
                            display_name=event.content.get("displayname"),
                        )

                        yield self._handle_new_user(room_id, state_key, profile)
                    else:  # The user left
                        yield self._handle_remove_user(room_id, state_key)
            else:
                logger.debug("Ignoring irrelevant type: %r", typ)

    @defer.inlineCallbacks
    def _handle_room_publicity_change(self, room_id, prev_event_id, event_id, typ):
        """Handle a room having potentially changed from/to world_readable/publically
        joinable.

        Args:
            room_id (str)
            prev_event_id (str|None): The previous event before the state change
            event_id (str|None): The new event after the state change
            typ (str): Type of the event
        """
        logger.debug("Handling change for %s: %s", typ, room_id)

        if typ == EventTypes.RoomHistoryVisibility:
            change = yield self._get_key_change(
                prev_event_id,
                event_id,
                key_name="history_visibility",
                public_value="world_readable",
            )
        elif typ == EventTypes.JoinRules:
            change = yield self._get_key_change(
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

        is_public = yield self.store.is_room_world_readable_or_publicly_joinable(
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

        users_with_profile = yield self.state.get_current_users_in_room(room_id)

        # Remove every user from the sharing tables for that room.
        for user_id in iterkeys(users_with_profile):
            yield self.store.remove_user_who_share_room(user_id, room_id)

        # Then, re-add them to the tables.
        # NOTE: this is not the most efficient method, as handle_new_user sets
        # up local_user -> other_user and other_user_whos_local -> local_user,
        # which when ran over an entire room, will result in the same values
        # being added multiple times. The batching upserts shouldn't make this
        # too bad, though.
        for user_id, profile in iteritems(users_with_profile):
            yield self._handle_new_user(room_id, user_id, profile)

    @defer.inlineCallbacks
    def _handle_local_user(self, user_id):
        """Adds a new local roomless user into the user_directory_search table.
        Used to populate up the user index when we have an
        user_directory_search_all_users specified.
        """
        logger.debug("Adding new local user to dir, %r", user_id)

        profile = yield self.store.get_profileinfo(get_localpart_from_id(user_id))

        row = yield self.store.get_user_in_directory(user_id)
        if not row:
            yield self.store.update_profile_in_user_dir(
                user_id, profile.display_name, profile.avatar_url
            )

    @defer.inlineCallbacks
    def _handle_new_user(self, room_id, user_id, profile):
        """Called when we might need to add user to directory

        Args:
            room_id (str): room_id that user joined or started being public
            user_id (str)
        """
        logger.debug("Adding new user to dir, %r", user_id)

        yield self.store.update_profile_in_user_dir(
            user_id, profile.display_name, profile.avatar_url
        )

        is_public = yield self.store.is_room_world_readable_or_publicly_joinable(
            room_id
        )
        # Now we update users who share rooms with users.
        users_with_profile = yield self.state.get_current_users_in_room(room_id)

        if is_public:
            yield self.store.add_users_in_public_rooms(room_id, (user_id,))
        else:
            to_insert = set()

            # First, if they're our user then we need to update for every user
            if self.is_mine_id(user_id):

                is_appservice = self.store.get_if_app_services_interested_in_user(
                    user_id
                )

                # We don't care about appservice users.
                if not is_appservice:
                    for other_user_id in users_with_profile:
                        if user_id == other_user_id:
                            continue

                        to_insert.add((user_id, other_user_id))

            # Next we need to update for every local user in the room
            for other_user_id in users_with_profile:
                if user_id == other_user_id:
                    continue

                is_appservice = self.store.get_if_app_services_interested_in_user(
                    other_user_id
                )
                if self.is_mine_id(other_user_id) and not is_appservice:
                    to_insert.add((other_user_id, user_id))

            if to_insert:
                yield self.store.add_users_who_share_private_room(room_id, to_insert)

    @defer.inlineCallbacks
    def _handle_remove_user(self, room_id, user_id):
        """Called when we might need to remove user from directory

        Args:
            room_id (str): room_id that user left or stopped being public that
            user_id (str)
        """
        logger.debug("Removing user %r", user_id)

        # Remove user from sharing tables
        yield self.store.remove_user_who_share_room(user_id, room_id)

        # Are they still in any rooms? If not, remove them entirely.
        rooms_user_is_in = yield self.store.get_user_dir_rooms_user_is_in(user_id)

        if len(rooms_user_is_in) == 0:
            yield self.store.remove_from_user_dir(user_id)

    @defer.inlineCallbacks
    def _handle_profile_change(self, user_id, room_id, prev_event_id, event_id):
        """Check member event changes for any profile changes and update the
        database if there are.
        """
        if not prev_event_id or not event_id:
            return

        prev_event = yield self.store.get_event(prev_event_id, allow_none=True)
        event = yield self.store.get_event(event_id, allow_none=True)

        if not prev_event or not event:
            return

        if event.membership != Membership.JOIN:
            return

        prev_name = prev_event.content.get("displayname")
        new_name = event.content.get("displayname")

        prev_avatar = prev_event.content.get("avatar_url")
        new_avatar = event.content.get("avatar_url")

        if prev_name != new_name or prev_avatar != new_avatar:
            yield self.store.update_profile_in_user_dir(user_id, new_name, new_avatar)
