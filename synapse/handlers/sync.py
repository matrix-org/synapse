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

from synapse.api.constants import Membership, EventTypes
from synapse.api.errors import GuestAccessError
from synapse.util import unwrapFirstError

from twisted.internet import defer

import collections
import logging

logger = logging.getLogger(__name__)


SyncConfig = collections.namedtuple("SyncConfig", [
    "user",
    "is_guest",
    "filter",
])


class TimelineBatch(collections.namedtuple("TimelineBatch", [
    "prev_batch",
    "events",
    "limited",
])):
    __slots__ = []

    def __nonzero__(self):
        """Make the result appear empty if there are no updates. This is used
        to tell if room needs to be part of the sync result.
        """
        return bool(self.events)


class JoinedSyncResult(collections.namedtuple("JoinedSyncResult", [
    "room_id",           # str
    "timeline",          # TimelineBatch
    "state",             # dict[(str, str), FrozenEvent]
    "ephemeral",
    "account_data",
])):
    __slots__ = []

    def __nonzero__(self):
        """Make the result appear empty if there are no updates. This is used
        to tell if room needs to be part of the sync result.
        """
        return bool(
            self.timeline
            or self.state
            or self.ephemeral
            or self.account_data
        )


class ArchivedSyncResult(collections.namedtuple("JoinedSyncResult", [
    "room_id",            # str
    "timeline",           # TimelineBatch
    "state",              # dict[(str, str), FrozenEvent]
    "account_data",
])):
    __slots__ = []

    def __nonzero__(self):
        """Make the result appear empty if there are no updates. This is used
        to tell if room needs to be part of the sync result.
        """
        return bool(
            self.timeline
            or self.state
            or self.account_data
        )


class InvitedSyncResult(collections.namedtuple("InvitedSyncResult", [
    "room_id",   # str
    "invite",    # FrozenEvent: the invite event
])):
    __slots__ = []

    def __nonzero__(self):
        """Invited rooms should always be reported to the client"""
        return True


class SyncResult(collections.namedtuple("SyncResult", [
    "next_batch",  # Token for the next sync
    "presence",  # List of presence events for the user.
    "account_data",  # List of account_data events for the user.
    "joined",  # JoinedSyncResult for each joined room.
    "invited",  # InvitedSyncResult for each invited room.
    "archived",  # ArchivedSyncResult for each archived room.
])):
    __slots__ = []

    def __nonzero__(self):
        """Make the result appear empty if there are no updates. This is used
        to tell if the notifier needs to wait for more events when polling for
        events.
        """
        return bool(
            self.presence or self.joined or self.invited
        )

GuestRoom = collections.namedtuple("GuestRoom", ("room_id", "membership"))


class SyncHandler(BaseHandler):

    def __init__(self, hs):
        super(SyncHandler, self).__init__(hs)
        self.event_sources = hs.get_event_sources()
        self.clock = hs.get_clock()

    @defer.inlineCallbacks
    def wait_for_sync_for_user(self, sync_config, since_token=None, timeout=0,
                               full_state=False):
        """Get the sync for a client if we have new data for it now. Otherwise
        wait for new data to arrive on the server. If the timeout expires, then
        return an empty sync result.
        Returns:
            A Deferred SyncResult.
        """

        if sync_config.is_guest:
            bad_rooms = []
            for room_id in sync_config.filter.list_rooms():
                world_readable = yield self._is_world_readable(room_id)
                if not world_readable:
                    bad_rooms.append(room_id)

            if bad_rooms:
                raise GuestAccessError(
                    bad_rooms, 403, "Guest access not allowed"
                )

        if timeout == 0 or since_token is None or full_state:
            # we are going to return immediately, so don't bother calling
            # notifier.wait_for_events.
            result = yield self.current_sync_for_user(sync_config, since_token,
                                                      full_state=full_state)
            defer.returnValue(result)
        else:
            def current_sync_callback(before_token, after_token):
                return self.current_sync_for_user(sync_config, since_token)

            result = yield self.notifier.wait_for_events(
                sync_config.user, timeout, current_sync_callback,
                from_token=since_token
            )
            defer.returnValue(result)

    @defer.inlineCallbacks
    def _is_world_readable(self, room_id):
        state = yield self.hs.get_state_handler().get_current_state(
            room_id,
            EventTypes.RoomHistoryVisibility
        )
        if state and "history_visibility" in state.content:
            defer.returnValue(state.content["history_visibility"] == "world_readable")
        else:
            defer.returnValue(False)

    def current_sync_for_user(self, sync_config, since_token=None,
                              full_state=False):
        """Get the sync for client needed to match what the server has now.
        Returns:
            A Deferred SyncResult.
        """
        if since_token is None or full_state:
            return self.full_state_sync(sync_config, since_token)
        else:
            return self.incremental_sync_with_gap(sync_config, since_token)

    @defer.inlineCallbacks
    def full_state_sync(self, sync_config, timeline_since_token):
        """Get a sync for a client which is starting without any state.

        If a 'message_since_token' is given, only timeline events which have
        happened since that token will be returned.

        Returns:
            A Deferred SyncResult.
        """
        now_token = yield self.event_sources.get_current_token()

        if sync_config.is_guest:
            room_list = [
                GuestRoom(room_id, Membership.JOIN)
                for room_id in sync_config.filter.list_rooms()
            ]

            account_data = {}
            account_data_by_room = {}
            tags_by_room = {}

        else:
            membership_list = (Membership.INVITE, Membership.JOIN)
            if sync_config.filter.include_leave:
                membership_list += (Membership.LEAVE, Membership.BAN)

            room_list = yield self.store.get_rooms_for_user_where_membership_is(
                user_id=sync_config.user.to_string(),
                membership_list=membership_list
            )

            account_data, account_data_by_room = (
                yield self.store.get_account_data_for_user(
                    sync_config.user.to_string()
                )
            )

            tags_by_room = yield self.store.get_tags_for_user(
                sync_config.user.to_string()
            )

        presence_stream = self.event_sources.sources["presence"]

        joined_room_ids = [
            room.room_id for room in room_list
            if room.membership == Membership.JOIN
        ]

        presence, _ = yield presence_stream.get_new_events(
            from_key=0,
            user=sync_config.user,
            room_ids=joined_room_ids,
            is_guest=sync_config.is_guest,
        )

        now_token, ephemeral_by_room = yield self.ephemeral_by_room(
            sync_config, now_token, joined_room_ids
        )

        joined = []
        invited = []
        archived = []
        deferreds = []
        for event in room_list:
            if event.membership == Membership.JOIN:
                room_sync_deferred = self.full_state_sync_for_joined_room(
                    room_id=event.room_id,
                    sync_config=sync_config,
                    now_token=now_token,
                    timeline_since_token=timeline_since_token,
                    ephemeral_by_room=ephemeral_by_room,
                    tags_by_room=tags_by_room,
                    account_data_by_room=account_data_by_room,
                )
                room_sync_deferred.addCallback(joined.append)
                deferreds.append(room_sync_deferred)
            elif event.membership == Membership.INVITE:
                invite = yield self.store.get_event(event.event_id)
                invited.append(InvitedSyncResult(
                    room_id=event.room_id,
                    invite=invite,
                ))
            elif event.membership in (Membership.LEAVE, Membership.BAN):
                leave_token = now_token.copy_and_replace(
                    "room_key", "s%d" % (event.stream_ordering,)
                )
                room_sync_deferred = self.full_state_sync_for_archived_room(
                    sync_config=sync_config,
                    room_id=event.room_id,
                    leave_event_id=event.event_id,
                    leave_token=leave_token,
                    timeline_since_token=timeline_since_token,
                    tags_by_room=tags_by_room,
                    account_data_by_room=account_data_by_room,
                )
                room_sync_deferred.addCallback(archived.append)
                deferreds.append(room_sync_deferred)

        yield defer.gatherResults(
            deferreds, consumeErrors=True
        ).addErrback(unwrapFirstError)

        defer.returnValue(SyncResult(
            presence=presence,
            account_data=self.account_data_for_user(account_data),
            joined=joined,
            invited=invited,
            archived=archived,
            next_batch=now_token,
        ))

    @defer.inlineCallbacks
    def full_state_sync_for_joined_room(self, room_id, sync_config,
                                        now_token, timeline_since_token,
                                        ephemeral_by_room, tags_by_room,
                                        account_data_by_room):
        """Sync a room for a client which is starting without any state
        Returns:
            A Deferred JoinedSyncResult.
        """

        batch = yield self.load_filtered_recents(
            room_id, sync_config, now_token, since_token=timeline_since_token
        )

        current_state = yield self.get_state_at(room_id, now_token)

        defer.returnValue(JoinedSyncResult(
            room_id=room_id,
            timeline=batch,
            state=current_state,
            ephemeral=ephemeral_by_room.get(room_id, []),
            account_data=self.account_data_for_room(
                room_id, tags_by_room, account_data_by_room
            ),
        ))

    def account_data_for_user(self, account_data):
        account_data_events = []

        for account_data_type, content in account_data.items():
            account_data_events.append({
                "type": account_data_type,
                "content": content,
            })

        return account_data_events

    def account_data_for_room(self, room_id, tags_by_room, account_data_by_room):
        account_data_events = []
        tags = tags_by_room.get(room_id)
        if tags is not None:
            account_data_events.append({
                "type": "m.tag",
                "content": {"tags": tags},
            })

        account_data = account_data_by_room.get(room_id, {})
        for account_data_type, content in account_data.items():
            account_data_events.append({
                "type": account_data_type,
                "content": content,
            })

        return account_data_events

    @defer.inlineCallbacks
    def ephemeral_by_room(self, sync_config, now_token, room_ids,
                          since_token=None):
        """Get the ephemeral events for each room the user is in
        Args:
            sync_config (SyncConfig): The flags, filters and user for the sync.
            now_token (StreamToken): Where the server is currently up to.
            room_ids (list): List of room id strings to get data for.
            since_token (StreamToken): Where the server was when the client
                last synced.
        Returns:
            A tuple of the now StreamToken, updated to reflect the which typing
            events are included, and a dict mapping from room_id to a list of
            typing events for that room.
        """

        typing_key = since_token.typing_key if since_token else "0"

        typing_source = self.event_sources.sources["typing"]
        typing, typing_key = yield typing_source.get_new_events(
            user=sync_config.user,
            from_key=typing_key,
            limit=sync_config.filter.ephemeral_limit(),
            room_ids=room_ids,
            is_guest=False,
        )
        now_token = now_token.copy_and_replace("typing_key", typing_key)

        ephemeral_by_room = {}

        for event in typing:
            # we want to exclude the room_id from the event, but modifying the
            # result returned by the event source is poor form (it might cache
            # the object)
            room_id = event["room_id"]
            event_copy = {k: v for (k, v) in event.iteritems()
                          if k != "room_id"}
            ephemeral_by_room.setdefault(room_id, []).append(event_copy)

        receipt_key = since_token.receipt_key if since_token else "0"

        receipt_source = self.event_sources.sources["receipt"]
        receipts, receipt_key = yield receipt_source.get_new_events(
            user=sync_config.user,
            from_key=receipt_key,
            limit=sync_config.filter.ephemeral_limit(),
            room_ids=room_ids,
            # /sync doesn't support guest access, they can't get to this point in code
            is_guest=False,
        )
        now_token = now_token.copy_and_replace("receipt_key", receipt_key)

        for event in receipts:
            room_id = event["room_id"]
            # exclude room id, as above
            event_copy = {k: v for (k, v) in event.iteritems()
                          if k != "room_id"}
            ephemeral_by_room.setdefault(room_id, []).append(event_copy)

        defer.returnValue((now_token, ephemeral_by_room))

    @defer.inlineCallbacks
    def full_state_sync_for_archived_room(self, room_id, sync_config,
                                          leave_event_id, leave_token,
                                          timeline_since_token, tags_by_room,
                                          account_data_by_room):
        """Sync a room for a client which is starting without any state
        Returns:
            A Deferred JoinedSyncResult.
        """

        batch = yield self.load_filtered_recents(
            room_id, sync_config, leave_token, since_token=timeline_since_token
        )

        leave_state = yield self.store.get_state_for_event(leave_event_id)

        defer.returnValue(ArchivedSyncResult(
            room_id=room_id,
            timeline=batch,
            state=leave_state,
            account_data=self.account_data_for_room(
                room_id, tags_by_room, account_data_by_room
            ),
        ))

    @defer.inlineCallbacks
    def incremental_sync_with_gap(self, sync_config, since_token):
        """ Get the incremental delta needed to bring the client up to
        date with the server.
        Returns:
            A Deferred SyncResult.
        """
        now_token = yield self.event_sources.get_current_token()

        if sync_config.is_guest:
            room_ids = sync_config.filter.list_rooms()

            tags_by_room = {}
            account_data = {}
            account_data_by_room = {}

        else:
            rooms = yield self.store.get_rooms_for_user(
                sync_config.user.to_string()
            )
            room_ids = [room.room_id for room in rooms]

            now_token, ephemeral_by_room = yield self.ephemeral_by_room(
                sync_config, now_token, since_token
            )

            tags_by_room = yield self.store.get_updated_tags(
                sync_config.user.to_string(),
                since_token.account_data_key,
            )

            account_data, account_data_by_room = (
                yield self.store.get_updated_account_data_for_user(
                    sync_config.user.to_string(),
                    since_token.account_data_key,
                )
            )

        now_token, ephemeral_by_room = yield self.ephemeral_by_room(
            sync_config, now_token, room_ids, since_token
        )

        presence_source = self.event_sources.sources["presence"]
        presence, presence_key = yield presence_source.get_new_events(
            user=sync_config.user,
            from_key=since_token.presence_key,
            limit=sync_config.filter.presence_limit(),
            room_ids=room_ids,
            is_guest=sync_config.is_guest,
        )
        now_token = now_token.copy_and_replace("presence_key", presence_key)

        rm_handler = self.hs.get_handlers().room_member_handler
        app_service = yield self.store.get_app_service_by_user_id(
            sync_config.user.to_string()
        )
        if app_service:
            rooms = yield self.store.get_app_service_rooms(app_service)
            joined_room_ids = set(r.room_id for r in rooms)
        else:
            joined_room_ids = yield rm_handler.get_joined_rooms_for_user(
                sync_config.user
            )

        timeline_limit = sync_config.filter.timeline_limit()

        room_events, _ = yield self.store.get_room_events_stream(
            sync_config.user.to_string(),
            from_key=since_token.room_key,
            to_key=now_token.room_key,
            limit=timeline_limit + 1,
            room_ids=room_ids if sync_config.is_guest else (),
            is_guest=sync_config.is_guest,
        )

        joined = []
        archived = []
        if len(room_events) <= timeline_limit:
            # There is no gap in any of the rooms. Therefore we can just
            # partition the new events by room and return them.
            logger.debug("Got %i events for incremental sync - not limited",
                         len(room_events))

            invite_events = []
            leave_events = []
            events_by_room_id = {}
            for event in room_events:
                events_by_room_id.setdefault(event.room_id, []).append(event)
                if event.room_id not in joined_room_ids:
                    if (event.type == EventTypes.Member
                            and event.state_key == sync_config.user.to_string()):
                        if event.membership == Membership.INVITE:
                            invite_events.append(event)
                        elif event.membership in (Membership.LEAVE, Membership.BAN):
                            leave_events.append(event)

            for room_id in joined_room_ids:
                recents = events_by_room_id.get(room_id, [])
                logger.debug("Events for room %s: %r", room_id, recents)
                state = {
                    (event.type, event.state_key): event
                    for event in recents if event.is_state()}
                limited = False

                if recents:
                    prev_batch = now_token.copy_and_replace(
                        "room_key", recents[0].internal_metadata.before
                    )
                else:
                    prev_batch = now_token

                just_joined = yield self.check_joined_room(sync_config, state)
                if just_joined:
                    logger.debug("User has just joined %s: needs full state",
                                 room_id)
                    state = yield self.get_state_at(room_id, now_token)
                    # the timeline is inherently limited if we've just joined
                    limited = True

                room_sync = JoinedSyncResult(
                    room_id=room_id,
                    timeline=TimelineBatch(
                        events=recents,
                        prev_batch=prev_batch,
                        limited=limited,
                    ),
                    state=state,
                    ephemeral=ephemeral_by_room.get(room_id, []),
                    account_data=self.account_data_for_room(
                        room_id, tags_by_room, account_data_by_room
                    ),
                )
                logger.debug("Result for room %s: %r", room_id, room_sync)

                if room_sync:
                    joined.append(room_sync)

        else:
            logger.debug("Got %i events for incremental sync - hit limit",
                         len(room_events))

            invite_events = yield self.store.get_invites_for_user(
                sync_config.user.to_string()
            )

            leave_events = yield self.store.get_leave_and_ban_events_for_user(
                sync_config.user.to_string()
            )

            for room_id in joined_room_ids:
                room_sync = yield self.incremental_sync_with_gap_for_room(
                    room_id, sync_config, since_token, now_token,
                    ephemeral_by_room, tags_by_room, account_data_by_room
                )
                if room_sync:
                    joined.append(room_sync)

        for leave_event in leave_events:
            room_sync = yield self.incremental_sync_for_archived_room(
                sync_config, leave_event, since_token, tags_by_room,
                account_data_by_room
            )
            archived.append(room_sync)

        invited = [
            InvitedSyncResult(room_id=event.room_id, invite=event)
            for event in invite_events
        ]

        defer.returnValue(SyncResult(
            presence=presence,
            account_data=self.account_data_for_user(account_data),
            joined=joined,
            invited=invited,
            archived=archived,
            next_batch=now_token,
        ))

    @defer.inlineCallbacks
    def load_filtered_recents(self, room_id, sync_config, now_token,
                              since_token=None):
        """
        :returns a Deferred TimelineBatch
        """
        limited = True
        recents = []
        filtering_factor = 2
        timeline_limit = sync_config.filter.timeline_limit()
        load_limit = max(timeline_limit * filtering_factor, 100)
        max_repeat = 3  # Only try a few times per room, otherwise
        room_key = now_token.room_key
        end_key = room_key

        while limited and len(recents) < timeline_limit and max_repeat:
            events, keys = yield self.store.get_recent_events_for_room(
                room_id,
                limit=load_limit + 1,
                from_token=since_token.room_key if since_token else None,
                end_token=end_key,
            )
            (room_key, _) = keys
            end_key = "s" + room_key.split('-')[-1]
            loaded_recents = sync_config.filter.filter_room_timeline(events)
            loaded_recents = yield self._filter_events_for_client(
                sync_config.user.to_string(),
                loaded_recents,
                is_guest=sync_config.is_guest,
                require_all_visible_for_guests=False
            )
            loaded_recents.extend(recents)
            recents = loaded_recents
            if len(events) <= load_limit:
                limited = False
            max_repeat -= 1

        if len(recents) > timeline_limit:
            limited = True
            recents = recents[-timeline_limit:]
            room_key = recents[0].internal_metadata.before

        prev_batch_token = now_token.copy_and_replace(
            "room_key", room_key
        )

        defer.returnValue(TimelineBatch(
            events=recents, prev_batch=prev_batch_token, limited=limited
        ))

    @defer.inlineCallbacks
    def incremental_sync_with_gap_for_room(self, room_id, sync_config,
                                           since_token, now_token,
                                           ephemeral_by_room, tags_by_room,
                                           account_data_by_room):
        """ Get the incremental delta needed to bring the client up to date for
        the room. Gives the client the most recent events and the changes to
        state.
        Returns:
            A Deferred JoinedSyncResult
        """
        logger.debug("Doing incremental sync for room %s between %s and %s",
                     room_id, since_token, now_token)

        # TODO(mjark): Check for redactions we might have missed.

        batch = yield self.load_filtered_recents(
            room_id, sync_config, now_token, since_token,
        )

        logging.debug("Recents %r", batch)

        current_state = yield self.get_state_at(room_id, now_token)

        state_at_previous_sync = yield self.get_state_at(
            room_id, stream_position=since_token
        )

        state = yield self.compute_state_delta(
            since_token=since_token,
            previous_state=state_at_previous_sync,
            current_state=current_state,
        )

        just_joined = yield self.check_joined_room(sync_config, state)
        if just_joined:
            state = yield self.get_state_at(room_id, now_token)

        room_sync = JoinedSyncResult(
            room_id=room_id,
            timeline=batch,
            state=state,
            ephemeral=ephemeral_by_room.get(room_id, []),
            account_data=self.account_data_for_room(
                room_id, tags_by_room, account_data_by_room
            ),
        )

        logging.debug("Room sync: %r", room_sync)

        defer.returnValue(room_sync)

    @defer.inlineCallbacks
    def incremental_sync_for_archived_room(self, sync_config, leave_event,
                                           since_token, tags_by_room,
                                           account_data_by_room):
        """ Get the incremental delta needed to bring the client up to date for
        the archived room.
        Returns:
            A Deferred ArchivedSyncResult
        """

        stream_token = yield self.store.get_stream_token_for_event(
            leave_event.event_id
        )

        leave_token = since_token.copy_and_replace("room_key", stream_token)

        batch = yield self.load_filtered_recents(
            leave_event.room_id, sync_config, leave_token, since_token,
        )

        logging.debug("Recents %r", batch)

        state_events_at_leave = yield self.store.get_state_for_event(
            leave_event.event_id
        )

        state_at_previous_sync = yield self.get_state_at(
            leave_event.room_id, stream_position=since_token
        )

        state_events_delta = yield self.compute_state_delta(
            since_token=since_token,
            previous_state=state_at_previous_sync,
            current_state=state_events_at_leave,
        )

        room_sync = ArchivedSyncResult(
            room_id=leave_event.room_id,
            timeline=batch,
            state=state_events_delta,
            account_data=self.account_data_for_room(
                leave_event.room_id, tags_by_room, account_data_by_room
            ),
        )

        logging.debug("Room sync: %r", room_sync)

        defer.returnValue(room_sync)

    @defer.inlineCallbacks
    def get_state_after_event(self, event):
        """
        Get the room state after the given event

        :param synapse.events.EventBase event: event of interest
        :return: A Deferred map from ((type, state_key)->Event)
        """
        state = yield self.store.get_state_for_event(event.event_id)
        if event.is_state():
            state = state.copy()
            state[(event.type, event.state_key)] = event
        defer.returnValue(state)

    @defer.inlineCallbacks
    def get_state_at(self, room_id, stream_position):
        """ Get the room state at a particular stream position
        :param str room_id: room for which to get state
        :param StreamToken stream_position: point at which to get state
        :returns: A Deferred map from ((type, state_key)->Event)
        """
        last_events, token = yield self.store.get_recent_events_for_room(
            room_id, end_token=stream_position.room_key, limit=1,
        )

        if last_events:
            last_event = last_events[-1]
            state = yield self.get_state_after_event(last_event)

        else:
            # no events in this room - so presumably no state
            state = {}
        defer.returnValue(state)

    def compute_state_delta(self, since_token, previous_state, current_state):
        """ Works out the differnce in state between the current state and the
        state the client got when it last performed a sync.

        :param str since_token: the point we are comparing against
        :param dict[(str,str), synapse.events.FrozenEvent] previous_state: the
            state to compare to
        :param dict[(str,str), synapse.events.FrozenEvent] current_state: the
            new state

        :returns A new event dictionary
        """
        # TODO(mjark) Check if the state events were received by the server
        # after the previous sync, since we need to include those state
        # updates even if they occured logically before the previous event.
        # TODO(mjark) Check for new redactions in the state events.

        state_delta = {}
        for key, event in current_state.iteritems():
            if (key not in previous_state or
                    previous_state[key].event_id != event.event_id):
                state_delta[key] = event
        return state_delta

    def check_joined_room(self, sync_config, state_delta):
        """
        Check if the user has just joined the given room (so should
        be given the full state)

        :param sync_config:
        :param dict[(str,str), synapse.events.FrozenEvent] state_delta: the
           difference in state since the last sync

        :returns A deferred Tuple (state_delta, limited)
        """
        join_event = state_delta.get((
            EventTypes.Member, sync_config.user.to_string()), None)
        if join_event is not None:
            if join_event.content["membership"] == Membership.JOIN:
                return True
        return False
