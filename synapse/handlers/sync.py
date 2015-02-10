# -*- coding: utf-8 -*-
# Copyright 2015 OpenMarket Ltd
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

from ._base import BaseHandler

from synapse.streams.config import PaginationConfig
from synapse.api.constants import Membership, EventTypes

from twisted.internet import defer

import collections
import logging

logger = logging.getLogger(__name__)


SyncConfig = collections.namedtuple("SyncConfig", [
    "user",
    "client_info",
    "limit",
    "gap",
    "sort",
    "backfill",
    "filter",
])


class RoomSyncResult(collections.namedtuple("RoomSyncResult", [
    "room_id",
    "limited",
    "published",
    "events",
    "state",
    "prev_batch",
    "ephemeral",
])):
    __slots__ = []

    def __nonzero__(self):
        """Make the result appear empty if there are no updates. This is used
        to tell if room needs to be part of the sync result.
        """
        return bool(self.events or self.state or self.ephemeral)


class SyncResult(collections.namedtuple("SyncResult", [
    "next_batch",  # Token for the next sync
    "private_user_data",  # List of private events for the user.
    "public_user_data",  # List of public events for all users.
    "rooms",  # RoomSyncResult for each room.
])):
    __slots__ = []

    def __nonzero__(self):
        """Make the result appear empty if there are no updates. This is used
        to tell if the notifier needs to wait for more events when polling for
        events.
        """
        return bool(
            self.private_user_data or self.public_user_data or self.rooms
        )


class SyncHandler(BaseHandler):

    def __init__(self, hs):
        super(SyncHandler, self).__init__(hs)
        self.event_sources = hs.get_event_sources()
        self.clock = hs.get_clock()

    @defer.inlineCallbacks
    def wait_for_sync_for_user(self, sync_config, since_token=None, timeout=0):
        """Get the sync for a client if we have new data for it now. Otherwise
        wait for new data to arrive on the server. If the timeout expires, then
        return an empty sync result.
        Returns:
            A Deferred SyncResult.
        """
        if timeout == 0 or since_token is None:
            result = yield self.current_sync_for_user(sync_config, since_token)
            defer.returnValue(result)
        else:
            def current_sync_callback():
                return self.current_sync_for_user(sync_config, since_token)

            rm_handler = self.hs.get_handlers().room_member_handler
            room_ids = yield rm_handler.get_rooms_for_user(sync_config.user)
            result = yield self.notifier.wait_for_events(
                sync_config.user, room_ids,
                sync_config.filter, timeout, current_sync_callback
            )
            defer.returnValue(result)

    def current_sync_for_user(self, sync_config, since_token=None):
        """Get the sync for client needed to match what the server has now.
        Returns:
            A Deferred SyncResult.
        """
        if since_token is None:
            return self.initial_sync(sync_config)
        else:
            if sync_config.gap:
                return self.incremental_sync_with_gap(sync_config, since_token)
            else:
                # TODO(mjark): Handle gapless sync
                raise NotImplementedError()

    @defer.inlineCallbacks
    def initial_sync(self, sync_config):
        """Get a sync for a client which is starting without any state
        Returns:
            A Deferred SyncResult.
        """
        if sync_config.sort == "timeline,desc":
            # TODO(mjark): Handle going through events in reverse order?.
            # What does "most recent events" mean when applying the limits mean
            # in this case?
            raise NotImplementedError()

        now_token = yield self.event_sources.get_current_token()

        presence_stream = self.event_sources.sources["presence"]
        # TODO (mjark): This looks wrong, shouldn't we be getting the presence
        # UP to the present rather than after the present?
        pagination_config = PaginationConfig(from_token=now_token)
        presence, _ = yield presence_stream.get_pagination_rows(
            user=sync_config.user,
            pagination_config=pagination_config.get_source_config("presence"),
            key=None
        )
        room_list = yield self.store.get_rooms_for_user_where_membership_is(
            user_id=sync_config.user.to_string(),
            membership_list=[Membership.INVITE, Membership.JOIN]
        )

        # TODO (mjark): Does public mean "published"?
        published_rooms = yield self.store.get_rooms(is_public=True)
        published_room_ids = set(r["room_id"] for r in published_rooms)

        rooms = []
        for event in room_list:
            room_sync = yield self.initial_sync_for_room(
                event.room_id, sync_config, now_token, published_room_ids
            )
            rooms.append(room_sync)

        defer.returnValue(SyncResult(
            public_user_data=presence,
            private_user_data=[],
            rooms=rooms,
            next_batch=now_token,
        ))

    @defer.inlineCallbacks
    def initial_sync_for_room(self, room_id, sync_config, now_token,
                              published_room_ids):
        """Sync a room for a client which is starting without any state
        Returns:
            A Deferred RoomSyncResult.
        """

        recents, prev_batch_token, limited = yield self.load_filtered_recents(
            room_id, sync_config, now_token,
        )

        current_state = yield self.state_handler.get_current_state(
            room_id
        )
        current_state_events = current_state.values()

        defer.returnValue(RoomSyncResult(
            room_id=room_id,
            published=room_id in published_room_ids,
            events=recents,
            prev_batch=prev_batch_token,
            state=current_state_events,
            limited=limited,
            ephemeral=[],
        ))

    @defer.inlineCallbacks
    def incremental_sync_with_gap(self, sync_config, since_token):
        """ Get the incremental delta needed to bring the client up to
        date with the server.
        Returns:
            A Deferred SyncResult.
        """
        if sync_config.sort == "timeline,desc":
            # TODO(mjark): Handle going through events in reverse order?.
            # What does "most recent events" mean when applying the limits mean
            # in this case?
            raise NotImplementedError()

        now_token = yield self.event_sources.get_current_token()

        presence_source = self.event_sources.sources["presence"]
        presence, presence_key = yield presence_source.get_new_events_for_user(
            user=sync_config.user,
            from_key=since_token.presence_key,
            limit=sync_config.limit,
        )
        now_token = now_token.copy_and_replace("presence_key", presence_key)

        typing_source = self.event_sources.sources["typing"]
        typing, typing_key = yield typing_source.get_new_events_for_user(
            user=sync_config.user,
            from_key=since_token.typing_key,
            limit=sync_config.limit,
        )
        now_token = now_token.copy_and_replace("typing_key", typing_key)

        typing_by_room = {event["room_id"]: [event] for event in typing}
        for event in typing:
            event.pop("room_id")
        logger.debug("Typing %r", typing_by_room)

        rm_handler = self.hs.get_handlers().room_member_handler
        room_ids = yield rm_handler.get_rooms_for_user(sync_config.user)

        # TODO (mjark): Does public mean "published"?
        published_rooms = yield self.store.get_rooms(is_public=True)
        published_room_ids = set(r["room_id"] for r in published_rooms)

        room_events, _ = yield self.store.get_room_events_stream(
            sync_config.user.to_string(),
            from_key=since_token.room_key,
            to_key=now_token.room_key,
            room_id=None,
            limit=sync_config.limit + 1,
        )

        rooms = []
        if len(room_events) <= sync_config.limit:
            # There is no gap in any of the rooms. Therefore we can just
            # partition the new events by room and return them.
            events_by_room_id = {}
            for event in room_events:
                events_by_room_id.setdefault(event.room_id, []).append(event)

            for room_id in room_ids:
                recents = events_by_room_id.get(room_id, [])
                state = [event for event in recents if event.is_state()]
                if recents:
                    prev_batch = now_token.copy_and_replace(
                        "room_key", recents[0].internal_metadata.before
                    )
                else:
                    prev_batch = now_token

                state = yield self.check_joined_room(
                    sync_config, room_id, state
                )

                room_sync = RoomSyncResult(
                    room_id=room_id,
                    published=room_id in published_room_ids,
                    events=recents,
                    prev_batch=prev_batch,
                    state=state,
                    limited=False,
                    ephemeral=typing_by_room.get(room_id, [])
                )
                if room_sync:
                    rooms.append(room_sync)
        else:
            for room_id in room_ids:
                room_sync = yield self.incremental_sync_with_gap_for_room(
                    room_id, sync_config, since_token, now_token,
                    published_room_ids, typing_by_room
                )
                if room_sync:
                    rooms.append(room_sync)

        defer.returnValue(SyncResult(
            public_user_data=presence,
            private_user_data=[],
            rooms=rooms,
            next_batch=now_token,
        ))

    @defer.inlineCallbacks
    def load_filtered_recents(self, room_id, sync_config, now_token,
                              since_token=None):
        limited = True
        recents = []
        filtering_factor = 2
        load_limit = max(sync_config.limit * filtering_factor, 100)
        max_repeat = 3  # Only try a few times per room, otherwise
        room_key = now_token.room_key
        end_key = room_key

        while limited and len(recents) < sync_config.limit and max_repeat:
            events, keys = yield self.store.get_recent_events_for_room(
                room_id,
                limit=load_limit + 1,
                from_token=since_token.room_key if since_token else None,
                end_token=end_key,
            )
            (room_key, _) = keys
            end_key = "s" + room_key.split('-')[-1]
            loaded_recents = sync_config.filter.filter_room_events(events)
            loaded_recents.extend(recents)
            recents = loaded_recents
            if len(events) <= load_limit:
                limited = False
            max_repeat -= 1

        if len(recents) > sync_config.limit:
            recents = recents[-sync_config.limit:]
            room_key = recents[0].internal_metadata.before

        prev_batch_token = now_token.copy_and_replace(
            "room_key", room_key
        )

        defer.returnValue((recents, prev_batch_token, limited))

    @defer.inlineCallbacks
    def incremental_sync_with_gap_for_room(self, room_id, sync_config,
                                           since_token, now_token,
                                           published_room_ids, typing_by_room):
        """ Get the incremental delta needed to bring the client up to date for
        the room. Gives the client the most recent events and the changes to
        state.
        Returns:
            A Deferred RoomSyncResult
        """

        # TODO(mjark): Check for redactions we might have missed.

        recents, prev_batch_token, limited = yield self.load_filtered_recents(
            room_id, sync_config, now_token, since_token,
        )

        logging.debug("Recents %r", recents)

        # TODO(mjark): This seems racy since this isn't being passed a
        # token to indicate what point in the stream this is
        current_state = yield self.state_handler.get_current_state(
            room_id
        )
        current_state_events = current_state.values()

        state_at_previous_sync = yield self.get_state_at_previous_sync(
            room_id, since_token=since_token
        )

        state_events_delta = yield self.compute_state_delta(
            since_token=since_token,
            previous_state=state_at_previous_sync,
            current_state=current_state_events,
        )

        state_events_delta = yield self.check_joined_room(
            sync_config, room_id, state_events_delta
        )

        room_sync = RoomSyncResult(
            room_id=room_id,
            published=room_id in published_room_ids,
            events=recents,
            prev_batch=prev_batch_token,
            state=state_events_delta,
            limited=limited,
            ephemeral=typing_by_room.get(room_id, [])
        )

        logging.debug("Room sync: %r", room_sync)

        defer.returnValue(room_sync)

    @defer.inlineCallbacks
    def get_state_at_previous_sync(self, room_id, since_token):
        """ Get the room state at the previous sync the client made.
        Returns:
            A Deferred list of Events.
        """
        last_events, token = yield self.store.get_recent_events_for_room(
            room_id, end_token=since_token.room_key, limit=1,
        )

        if last_events:
            last_event = last_events[0]
            last_context = yield self.state_handler.compute_event_context(
                last_event
            )
            if last_event.is_state():
                state = [last_event] + last_context.current_state.values()
            else:
                state = last_context.current_state.values()
        else:
            state = ()
        defer.returnValue(state)

    def compute_state_delta(self, since_token, previous_state, current_state):
        """ Works out the differnce in state between the current state and the
        state the client got when it last performed a sync.
        Returns:
            A list of events.
        """
        # TODO(mjark) Check if the state events were received by the server
        # after the previous sync, since we need to include those state
        # updates even if they occured logically before the previous event.
        # TODO(mjark) Check for new redactions in the state events.
        previous_dict = {event.event_id: event for event in previous_state}
        state_delta = []
        for event in current_state:
            if event.event_id not in previous_dict:
                state_delta.append(event)
        return state_delta

    @defer.inlineCallbacks
    def check_joined_room(self, sync_config, room_id, state_delta):
        joined = False
        for event in state_delta:
            if (
                event.type == EventTypes.Member
                and event.state_key == sync_config.user.to_string()
            ):
                if event.content["membership"] == Membership.JOIN:
                    joined = True

        if joined:
            res = yield self.state_handler.get_current_state(room_id)
            state_delta = res.values()

        defer.returnValue(state_delta)
