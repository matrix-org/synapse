# -*- coding: utf-8 -*-
# Copyright 2018 New Vector Ltd
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

from synapse.api.constants import EventTypes, Membership
from synapse.types import get_localpart_from_id
from synapse.util.metrics import Measure

logger = logging.getLogger(__name__)


class StatsHandler(object):
    """Handles keeping the *_stats tables updated with a simple time-series of
    information about the users, rooms and media on the server, such that admins
    have some idea of who is consuming their resouces.

    Heavily derived from UserDirectoryHandler
    """

    INITIAL_ROOM_SLEEP_MS = 50
    INITIAL_ROOM_SLEEP_COUNT = 100
    INITIAL_ROOM_BATCH_SIZE = 100
    INITIAL_USER_SLEEP_MS = 10

    def __init__(self, hs):
        self.store = hs.get_datastore()
        self.state = hs.get_state_handler()
        self.server_name = hs.hostname
        self.clock = hs.get_clock()
        self.notifier = hs.get_notifier()
        self.is_mine_id = hs.is_mine_id
        self.stats_enable = hs.config.stats_enable
        self.stats_bucket_size = hs.config.stats_bucket_size

        # The current position in the current_state_delta stream
        self.pos = None

        # Guard to ensure we only process deltas one at a time
        self._is_processing = False

        if self.stats_enable:
            self.notifier.add_replication_callback(self.notify_new_event)

            # We kick this off so that we don't have to wait for a change before
            # we start populating stats
            self.clock.call_later(0, self.notify_new_event)

    @defer.inlineCallbacks
    def notify_new_event(self):
        """Called when there may be more deltas to process
        """
        if not self.stats_enable:
            return

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
            self.pos = yield self.store.get_stats_stream_pos()

        # If still None then we need to do the initial fill of stats
        if self.pos is None:
            yield self._do_initial_spam()
            self.pos = yield self.store.get_stats_stream_pos()

        # Loop round handling deltas until we're up to date
        while True:
            with Measure(self.clock, "stats_delta"):
                deltas = yield self.store.get_current_state_deltas(self.pos)
                if not deltas:
                    return

                logger.info("Handling %d state deltas", len(deltas))
                yield self._handle_deltas(deltas)

                self.pos = deltas[-1]["stream_id"]
                yield self.store.update_stats_stream_pos(self.pos)

    @defer.inlineCallbacks
    def _do_initial_spam(self):
        """Populates the stats tables from the current state of the DB, used
        when synapse first starts with stats support
        """
        new_pos = yield self.store.get_max_stream_id_in_current_state_deltas()

        # We process by going through each existing room at a time.
        room_ids = yield self.store.get_all_rooms()

        logger.info("Doing initial update of room_stats. %d rooms", len(room_ids))
        num_processed_rooms = 0

        for room_id in room_ids:
            logger.info("Handling room %d/%d", num_processed_rooms + 1, len(room_ids))
            yield self._handle_initial_room(room_id)
            num_processed_rooms += 1
            yield self.clock.sleep(self.INITIAL_ROOM_SLEEP_MS / 1000.)

        logger.info("Processed all rooms.")

        num_processed_users = 0
        user_ids = yield self.store.get_all_local_users()
        logger.info("Doing initial update user_stats. %d users", len(user_ids))
        for user_id in user_ids:
            logger.info("Handling user %d/%d", num_processed_users + 1, len(user_ids))
            yield self._handle_local_user(user_id)
            num_processed_users += 1
            yield self.clock.sleep(self.INITIAL_USER_SLEEP_MS / 1000.)

        logger.info("Processed all users")

        yield self.store.update_stats_stream_pos(new_pos)

    @defer.inlineCallbacks
    def _handle_initial_room(self, room_id):
        """Called when we initially fill out stats one room at a time
        """

        current_state_ids = yield self.store.get_current_state_ids(room_id)

        join_rules = yield self.store.get_event(
            current_state_ids.get((EventTypes.JoinRules, ""))
        )
        history_visibility = yield self.store.get_event(
            current_state_ids.get((EventTypes.RoomHistoryVisibility, ""))
        )
        encryption = yield self.store.get_event(
            current_state_ids.get((EventTypes.RoomEncryption, ""))
        )
        name = yield self.store.get_event(
            current_state_ids.get((EventTypes.Name, ""))
        )
        topic = yield self.store.get_event(
            current_state_ids.get((EventTypes.Topic, ""))
        )
        avatar = yield self.store.get_event(
            current_state_ids.get((EventTypes.RoomAvatar, ""))
        )
        canonical_alias = yield self.store.get_event(
            current_state_ids.get((EventTypes.CanonicalAlias, ""))
        )

        yield self.store.update_room_state(
            room_id,
            {
                "join_rules": join_rules.content.get("join_rule")
                if join_rules else None,
                "history_visibility": history_visibility.content.get("history_visibility")
                if history_visibility else None,
                "encryption": encryption.content.get("algorithm")
                if encryption else None,
                "name": name.content.get("name")
                if name else None,
                "topic": name.content.get("topic")
                if topic else None,
                "avatar": name.content.get("url")
                if avatar else None,
                "canonical_alias": name.content.get("alias")
                if canonical_alias else None,
            }
        )

        now = self.clock.time_msec()

        # quantise time to the nearest bucket
        now = int(now / (self.stats_bucket_size * 1000)) * self.stats_bucket_size * 1000

        current_state_events = len(current_state_ids)
        joined_members = yield self.store.get_user_count_in_room(
            room_id, Membership.JOIN
        )
        invited_members = yield self.store.get_user_count_in_room(
            room_id, Membership.INVITE
        )
        left_members = yield self.store.get_user_count_in_room(
            room_id, Membership.LEAVE
        )
        banned_members = yield self.store.get_user_count_in_room(
            room_id, Membership.BAN
        )
        state_events = yield self.store.get_state_event_counts(room_id)
        (local_events, remote_events) = yield self.store.get_event_counts(
            room_id, self.server_name
        )

        yield self.store.delete_room_stats(room_id, now)

        self.store.update_room_stats(
            room_id,
            now,
            {
                "bucket_size": self.stats_bucket_size,
                "current_state_events": current_state_events,
                "joined_members": joined_members,
                "invited_members": invited_members,
                "left_members": left_members,
                "banned_members": banned_members,
                "state_events": state_events,
                "local_events": local_events,
                "remote_events": remote_events,
            }
        )

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
            yield self.store.add_profiles_to_user_dir(None, {user_id: profile})
