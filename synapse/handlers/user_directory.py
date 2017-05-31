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

from twisted.internet import defer

from synapse.api.constants import EventTypes, JoinRules, Membership
from synapse.storage.roommember import ProfileInfo
from synapse.util.metrics import Measure


logger = logging.getLogger(__name__)


class UserDirectoyHandler(object):
    """Handles querying of and keeping updated the user_directory.

    N.B.: ASSUMES IT IS THE ONLY THING THAT MODIFIES THE USER DIRECTORY
    """

    def __init__(self, hs):
        self.store = hs.get_datastore()
        self.state = hs.get_state_handler()
        self.server_name = hs.hostname
        self.clock = hs.get_clock()

        # When start up for the first time we need to populate the user_directory.
        # This is a set of user_id's we've inserted already
        self.initially_handled_users = set()

        # The current position in the current_state_delta stream
        self.pos = None

        # Guard to ensure we only process deltas one at a time
        self._is_processing = False

        # We kick this off so that we don't have to wait for a change before
        # we start populating the user directory
        self.clock.call_later(0, self.notify_new_event)

    def search_users(self, search_term, limit):
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
        return self.store.search_user_dir(search_term, limit)

    @defer.inlineCallbacks
    def notify_new_event(self):
        """Called when there may be more deltas to process
        """
        if self._is_processing:
            return

        self._is_processing = True
        try:
            yield self._unsafe_process()
        finally:
            self._is_processing = False

    @defer.inlineCallbacks
    def _unsafe_process(self):
        # If self.pos is None then means we haven't fetched it from DB
        if self.pos is None:
            self.pos = yield self.store.get_user_directory_stream_pos()

        # If still None then we need to do the initial fill of directory
        if self.pos is None:
            yield self._do_initial_spam()
            self.pos = yield self.store.get_user_directory_stream_pos()

        # Loop round handling deltas until we're up to date
        while True:
            with Measure(self.clock, "user_dir_delta"):
                deltas = yield self.store.get_current_state_deltas(self.pos)
                if not deltas:
                    return

                yield self._handle_deltas(deltas)

                self.pos = deltas[-1]["stream_id"]
                yield self.store.update_user_directory_stream_pos(self.pos)

    @defer.inlineCallbacks
    def _do_initial_spam(self):
        """Populates the user_directory from the current state of the DB, used
        when synapse first starts with user_directory support
        """
        new_pos = yield self.store.get_max_stream_id_in_current_state_deltas()

        # Delete any existing entries just in case there are any
        yield self.store.delete_all_from_user_dir()

        # We process by going through each existing room at a time.
        room_ids = yield self.store.get_all_rooms()

        for room_id in room_ids:
            yield self._handle_intial_room(room_id)

        self.initially_handled_users = None

        yield self.store.update_user_directory_stream_pos(new_pos)

    @defer.inlineCallbacks
    def _handle_intial_room(self, room_id):
        """Called when we initially fill out user_directory one room at a time
        """
        is_in_room = yield self.state.get_is_host_in_room(room_id, self.server_name)
        if not is_in_room:
            return

        is_public = yield self.store.is_room_world_readable_or_publicly_joinable(room_id)
        if not is_public:
            return

        users_with_profile = yield self.state.get_current_user_in_room(room_id)
        unhandled_users = set(users_with_profile) - self.initially_handled_users

        yield self.store.add_profiles_to_user_dir(
            room_id, {
                user_id: users_with_profile[user_id] for user_id in unhandled_users
            }
        )

        self.initially_handled_users |= unhandled_users

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

            # For join rule and visibility changes we need to check if the room
            # may have become public or not and add/remove the users in said room
            if typ == EventTypes.RoomHistoryVisibility:
                change = yield self._get_key_change(
                    prev_event_id, event_id,
                    key_name="history_visibility",
                    public_value="world_readable",
                )

                # If change is None, no change. True => become world readable,
                # False => was world readable
                if change is None:
                    continue

                # There's been a change to or from being world readable.

                is_public = yield self.store.is_room_world_readable_or_publicly_joinable(
                    room_id
                )

                if change and not is_public:
                    # If we became world readable but room isn't currently public then
                    # we ignore the change
                    continue
                elif not change and is_public:
                    # If we stopped being world readable but are still public,
                    # ignore the change
                    continue

                users_with_profile = yield self.state.get_current_user_in_room(room_id)
                for user_id, profile in users_with_profile.iteritems():
                    if change:
                        yield self._handle_new_user(room_id, user_id, profile)
                    else:
                        yield self._handle_remove_user(room_id, user_id)
            elif typ == EventTypes.JoinRules:
                change = yield self._get_key_change(
                    prev_event_id, event_id,
                    key_name="join_rules",
                    public_value=JoinRules.PUBLIC,
                )
                if change is None:
                    continue

                is_public = yield self.store.is_room_world_readable_or_publicly_joinable(
                    room_id
                )

                if change and is_public:
                    continue
                elif not change and not is_public:
                    continue

                users_with_profile = yield self.state.get_current_user_in_room(room_id)
                for user_id, profile in users_with_profile.iteritems():
                    if change:
                        yield self._handle_new_user(room_id, user_id, profile)
                    else:
                        yield self._handle_remove_user(room_id, user_id)
            elif typ == EventTypes.Member:
                change = yield self._get_key_change(
                    prev_event_id, event_id,
                    key_name="membership",
                    public_value=Membership.JOIN,
                )

                if change is None:
                    continue

                if not change:
                    # Need to check if the server left the room entirely, if so
                    # we might need to remove all the users in that room
                    is_in_room = yield self.state.get_is_host_in_room(
                        room_id, self.server_name,
                    )
                    if not is_in_room:
                        # Fetch all the users that we marked as being in user
                        # directory due to being in the room and then check if
                        # need to remove those users or not
                        user_ids = yield self.store.get_users_in_dir_due_to_room(room_id)
                        for user_id in user_ids:
                            yield self._handle_remove_user(room_id, user_id)
                        return

                if change:  # The user joined
                    event = yield self.store.get_event(event_id)
                    profile = ProfileInfo(
                        avatar_url=event.content.get("avatar_url"),
                        display_name=event.content.get("displayname"),
                    )

                    yield self._handle_new_user(room_id, state_key, profile)
                else:  # The user left
                    yield self._handle_remove_user(room_id, state_key)

    @defer.inlineCallbacks
    def _handle_new_user(self, room_id, user_id, profile):
        """Called when we might need to add user to directory

        Args:
            room_id (str): room_id that user joined or started being public that
            user_id (str)
        """
        row = yield self.store.get_user_in_directory(user_id)
        if row:
            return

        yield self.store.add_profiles_to_user_dir(room_id, {user_id: profile})

    def _handle_remove_user(self, room_id, user_id):
        """Called when we might need to remove user to directory

        Args:
            room_id (str): room_id that user left or stopped being public that
            user_id (str)
        """
        row = yield self.store.get_user_in_directory(user_id)
        if not row or row["room_id"] != room_id:
            # Either the user wasn't in directory or we're still in a room that
            # is public (i.e. the room_id in the database)
            return

        # XXX: Make this faster?
        rooms = yield self.store.get_rooms_for_user(user_id)
        for j_room_id in rooms:
            is_public = yield self.store.is_room_world_readable_or_publicly_joinable(
                j_room_id
            )

            if is_public:
                yield self.store.update_user_in_user_dir(user_id, j_room_id)
                return

        yield self.store.remove_from_user_dir(user_id)

    @defer.inlineCallbacks
    def _get_key_change(self, prev_event_id, event_id, key_name, public_value):
        """Given two events check if the `key_name` field in content changed
        from not matching `public_value` to doing so.

        For example, check if `history_visibility` (`key_name`) changed from
        `shared` to `world_readable` (`public_value`).

        Returns:
            None if the field in the events either both match `public_value`
            neither do, i.e. there has been no change.
            True if it didnt match `public_value` but now does
            False if it did match `public_value` but now doesn't
        """
        prev_event = None
        event = None
        if prev_event_id:
            prev_event = yield self.store.get_event(prev_event_id, allow_none=True)

        if event_id:
            event = yield self.store.get_event(event_id, allow_none=True)

        if not event and not prev_event:
            defer.returnValue(None)

        prev_value = None
        value = None

        if prev_event:
            prev_value = prev_event.content.get(key_name, None)

        if event:
            value = event.content.get(key_name, None)

        if value == public_value and prev_value != public_value:
            defer.returnValue(True)
        elif value != public_value and prev_value == public_value:
            defer.returnValue(False)
        else:
            defer.returnValue(None)
