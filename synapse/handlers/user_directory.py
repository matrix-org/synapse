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
    def __init__(self, hs):
        self.store = hs.get_datastore()
        self.state = hs.get_state_handler()
        self.server_name = hs.hostname
        self.clock = hs.get_clock()

        self.initially_handled_users = set()

        self.pos = None

        self._is_processing = False

        self.clock.call_later(0, self.notify_new_event)

    def search_users(self, search_term, limit):
        return self.store.search_user_dir(search_term, limit)

    @defer.inlineCallbacks
    def notify_new_event(self):
        if self._is_processing:
            return

        self._is_processing = True
        try:
            yield self._unsafe_process()
        finally:
            self._is_processing = False

    @defer.inlineCallbacks
    def _unsafe_process(self):
        if self.pos is None:
            self.pos = yield self.store.get_user_directory_stream_pos()

        if self.pos is None:
            yield self._do_initial_spam()
            self.pos = yield self.store.get_user_directory_stream_pos()

        while True:
            with Measure(self.clock, "user_dir_delta"):
                deltas = yield self.store.get_current_state_deltas(self.pos)
                if not deltas:
                    return

                yield self._handle_deltas(deltas)

                self.pos = deltas[-1]["stream_id"]
                yield self.store.update_user_directory_stream_pos(self.pos)

    @defer.inlineCallbacks
    def _handle_room(self, room_id):
        # TODO: Check we're still joined to room

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
    def _do_initial_spam(self):
        # TODO: pull from current delta stream_id
        new_pos = self.store.get_room_max_stream_ordering()

        yield self.store.delete_all_from_user_dir()

        room_ids = yield self.store.get_all_rooms()

        for room_id in room_ids:
            yield self._handle_room(room_id)

        self.initially_handled_users = None

        yield self.store.update_user_directory_stream_pos(new_pos)

    @defer.inlineCallbacks
    def _handle_new_user(self, room_id, user_id, profile):
        row = yield self.store.get_user_in_directory(user_id)
        if row:
            return

        yield self.store.add_profiles_to_user_dir(room_id, {user_id: profile})

    def _handle_remove_user(self, room_id, user_id):
        row = yield self.store.get_user_in_directory(user_id)
        if not row or row["room_id"] != room_id:
            return

        # TODO: Make this faster?
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
    def _handle_deltas(self, deltas):
        for delta in deltas:
            typ = delta["type"]
            state_key = delta["state_key"]
            room_id = delta["room_id"]
            event_id = delta["event_id"]
            prev_event_id = delta["prev_event_id"]

            if typ == EventTypes.RoomHistoryVisibility:
                change = yield self._get_key_change(
                    prev_event_id, event_id,
                    key_name="history_visibility",
                    public_value="world_readable",
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

                if change:
                    event = yield self.store.get_event(event_id)
                    profile = ProfileInfo(
                        avatar_url=event.content.get("avatar_url"),
                        display_name=event.content.get("displayname"),
                    )

                    yield self._handle_new_user(room_id, state_key, profile)
                else:
                    yield self._handle_remove_user(room_id, state_key)

    @defer.inlineCallbacks
    def _get_key_change(self, prev_event_id, event_id, key_name, public_value):
        prev_event = None
        event = None
        if prev_event_id:
            prev_event = yield self.store.get_event(prev_event_id, allow_none=True)

        if event_id:
            event = yield self.store.get_event(event_id, allow_none=True)

        if not event and not prev_event:
            defer.returnValue(None)

        prev_hist_vis = None
        hist_vis = None

        if prev_event:
            prev_hist_vis = prev_event.content.get(key_name, None)

        if event:
            hist_vis = event.content.get(key_name, None)

        if hist_vis == public_value and prev_hist_vis != public_value:
            defer.returnValue(True)
        elif hist_vis != public_value and prev_hist_vis == public_value:
            defer.returnValue(False)
        else:
            defer.returnValue(None)
