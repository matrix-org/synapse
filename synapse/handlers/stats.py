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

from synapse.api.constants import EventTypes, JoinRules, Membership
from synapse.handlers.state_deltas import StateDeltasHandler
from synapse.metrics.background_process_metrics import run_as_background_process
from synapse.types import UserID
from synapse.util import logcontext
from synapse.util.metrics import Measure

logger = logging.getLogger(__name__)


class StatsHandler(StateDeltasHandler):
    """Handles keeping the *_stats tables updated with a simple time-series of
    information about the users, rooms and media on the server, such that admins
    have some idea of who is consuming their resources.

    Heavily derived from UserDirectoryHandler
    """

    def __init__(self, hs):
        super(StatsHandler, self).__init__(hs)
        self.hs = hs
        self.store = hs.get_datastore()
        self.state = hs.get_state_handler()
        self.server_name = hs.hostname
        self.clock = hs.get_clock()
        self.notifier = hs.get_notifier()
        self.is_mine_id = hs.is_mine_id
        self.stats_bucket_size = hs.config.stats_bucket_size

        # The current position in the current_state_delta stream
        self.pos = None

        # Guard to ensure we only process deltas one at a time
        self._is_processing = False

        if hs.config.stats_enable:
            self.notifier.add_replication_callback(self.notify_new_event)

            # We kick this off so that we don't have to wait for a change before
            # we start populating stats
            self.clock.call_later(0, self.notify_new_event)

    def notify_new_event(self):
        """Called when there may be more deltas to process
        """
        if not self.hs.config.stats_enable:
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
        run_as_background_process("stats.notify_new_event", process)

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
            with Measure(self.clock, "stats_delta"):
                with logcontext.PreserveLoggingContext():
                    deltas = yield self.store.get_current_state_deltas(self.pos)
                    if not deltas:
                        return

                    logger.info("Handling %d state deltas", len(deltas))
                    yield self._handle_deltas(deltas)

                    self.pos = deltas[-1]["stream_id"]
                    yield self.store.update_stats_stream_pos(self.pos)

    @defer.inlineCallbacks
    def _handle_deltas(self, deltas):
        """
        Called with the state deltas to process
        """

        # XXX: shouldn't this be the timestamp where the delta was emitted rather
        # than received?
        now = self.clock.time_msec()

        # quantise time to the nearest bucket
        now = int(now / (self.stats_bucket_size * 1000)) * self.stats_bucket_size * 1000

        for delta in deltas:
            typ = delta["type"]
            state_key = delta["state_key"]
            room_id = delta["room_id"]
            event_id = delta["event_id"]
            prev_event_id = delta["prev_event_id"]

            logger.debug("Handling: %r %r, %s", typ, state_key, event_id)

            if event_id is None:
                return

            event = yield self.store.get_event(event_id)
            if event is None:
                return

            if typ == EventTypes.Member:
                # we could use _get_key_change here but it's a bit inefficient
                # given we're not testing for a specific result; might as well
                # just grab the prev_membership and membership strings and
                # compare them.
                prev_event = None
                if prev_event_id is not None:
                    prev_event = yield self.store.get_event(prev_event_id)

                prev_membership = None
                membership = event.content.get("membership")
                if prev_event:
                    prev_membership = prev_event.content.get("membership")

                if prev_membership != membership:
                    if prev_membership == Membership.JOIN:
                        yield self.store.update_stats_delta(
                            now,
                            self.stats_bucket_size,
                            "room",
                            room_id,
                            "joined_members",
                            -1,
                        )
                    elif prev_membership == Membership.INVITE:
                        yield self.store.update_stats_delta(
                            now,
                            self.stats_bucket_size,
                            "room",
                            room_id,
                            "invited_members",
                            -1,
                        )
                    elif prev_membership == Membership.LEAVE:
                        yield self.store.update_stats_delta(
                            now,
                            self.stats_bucket_size,
                            "room",
                            room_id,
                            "left_members",
                            -1,
                        )
                    elif prev_membership == Membership.BAN:
                        yield self.store.update_stats_delta(
                            now,
                            self.stats_bucket_size,
                            "room",
                            room_id,
                            "banned_members",
                            -1,
                        )

                    if membership == Membership.JOIN:
                        yield self.store.update_stats_delta(
                            now,
                            self.stats_bucket_size,
                            "room",
                            room_id,
                            "joined_members",
                            +1,
                        )
                    elif membership == Membership.INVITE:
                        yield self.store.update_stats_delta(
                            now,
                            self.stats_bucket_size,
                            "room",
                            room_id,
                            "invited_members",
                            +1,
                        )
                    elif membership == Membership.LEAVE:
                        yield self.store.update_stats_delta(
                            now,
                            self.stats_bucket_size,
                            "room",
                            room_id,
                            "left_members",
                            +1,
                        )
                    elif membership == Membership.BAN:
                        yield self.store.update_stats_delta(
                            now,
                            self.stats_bucket_size,
                            "room",
                            room_id,
                            "banned_members",
                            +1,
                        )

                user_id = event.state_key
                if self.is_mine_id(user_id):
                    # update user_stats as it's one of our users
                    public = yield self._is_public_room(room_id)

                    if prev_membership != membership:
                        if prev_membership == Membership.JOIN:
                            yield self.store.update_stats_delta(
                                now,
                                self.stats_bucket_size,
                                "user",
                                user_id,
                                "public_rooms" if public else "private_rooms",
                                -1,
                            )
                        elif membership == Membership.JOIN:
                            yield self.store.update_stats_delta(
                                now,
                                self.stats_bucket_size,
                                "user",
                                user_id,
                                "public_rooms" if public else "private_rooms",
                                +1,
                            )

            elif typ == EventTypes.Create:
                # Newly created room. Add it with all blank portions.
                yield self.store.update_room_state(
                    room_id,
                    {
                        "join_rules": None,
                        "history_visibility": None,
                        "encryption": None,
                        "name": None,
                        "topic": None,
                        "avatar": None,
                        "canonical_alias": None,
                    },
                )

            elif typ == EventTypes.JoinRules:
                self.store.update_room_state(
                    room_id, {"join_rules": event.content.get("join_rule")}
                )

                is_public = self._get_key_change(
                    prev_event_id, event_id, "join_rule", JoinRules.PUBLIC
                )
                if is_public is not None:
                    self.update_public_room_stats(
                        now, self.stats_bucket_size, room_id, is_public
                    )

            elif typ == EventTypes.RoomHistoryVisibility:
                yield self.store.update_room_state(
                    room_id,
                    {"history_visibility": event.content.get("history_visibility")},
                )

                is_public = self._get_key_change(
                    prev_event_id, event_id, "history_visibility", "world_readable"
                )
                if is_public is not None:
                    yield self.update_public_room_stats(
                        now, self.stats_bucket_size, room_id, is_public
                    )

            elif typ == EventTypes.Encryption:
                self.store.update_room_state(
                    room_id, {"encryption": event.content.get("algorithm")}
                )
            elif typ == EventTypes.Name:
                self.store.update_room_state(
                    room_id, {"name": event.content.get("name")}
                )
            elif typ == EventTypes.Topic:
                self.store.update_room_state(
                    room_id, {"topic": event.content.get("topic")}
                )
            elif typ == EventTypes.RoomAvatar:
                self.store.update_room_state(
                    room_id, {"avatar": event.content.get("url")}
                )
            elif typ == EventTypes.CanonicalAlias:
                self.store.update_room_state(
                    room_id, {"canonical_alias": event.content.get("alias")}
                )

    @defer.inlineCallbacks
    def update_public_room_stats(self, ts, bucket_size, room_id, is_public):
        # For now, blindly iterate over all local users in the room so that
        # we can handle the whole problem of copying buckets over as needed

        user_ids = yield self.store.get_users_in_room(room_id)

        for user_id in user_ids:
            if self.hs.is_mine(UserID.from_string(user_id)):
                self.store.update_stats_delta(
                    ts,
                    bucket_size,
                    "user",
                    user_id,
                    "public_rooms",
                    +1 if is_public else -1,
                )
                self.store.update_stats_delta(
                    ts,
                    bucket_size,
                    "user",
                    user_id,
                    "private_rooms",
                    -1 if is_public else +1,
                )

    @defer.inlineCallbacks
    def _is_public_room(self, room_id):
        join_rules = yield self.state.get_current_state(room_id, EventTypes.JoinRules)
        history_visibility = yield self.state.get_current_state(
            room_id, EventTypes.RoomHistoryVisibility
        )

        if (join_rules and join_rules.content.get("join_rule") == JoinRules.PUBLIC) or (
            (
                history_visibility
                and history_visibility.content.get("history_visibility")
                == "world_readable"
            )
        ):
            defer.returnValue(True)
        else:
            defer.returnValue(False)

    @defer.inlineCallbacks
    def _handle_local_user(self, user_id):
        logger.debug("Adding new local user to stats, %r", user_id)

        yield defer.succeed(1)
