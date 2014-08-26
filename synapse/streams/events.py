# -*- coding: utf-8 -*-
# Copyright 2014 matrix.org
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

from twisted.internet import defer

from synapse.api.constants import Membership
from synapse.types import StreamToken


class RoomEventSource(object):
    SIGNAL_NAME = "RoomEventSource"

    def __init__(self, hs):
        self.store = hs.get_datastore()

    @defer.inlineCallbacks
    def get_keys_for_user(self, user):
        events = yield self.store.get_rooms_for_user_where_membership_is(
            user.to_string(),
            (Membership.JOIN,),
        )

        defer.returnValue(set([e.room_id for e in events]))

    @defer.inlineCallbacks
    def get_new_events_for_user(self, user, from_token, limit, key=None):
        # We just ignore the key for now.

        to_key = yield self.get_current_token_part()

        events, end_key = yield self.store.get_room_events_stream(
            user_id=user.to_string(),
            from_key=from_token.events_key,
            to_key=to_key,
            room_id=None,
            limit=limit,
        )

        end_token = from_token.copy_and_replace("events_key", end_key)

        defer.returnValue((events, end_token))

    def get_current_token_part(self):
        return self.store.get_room_events_max_id()

    @defer.inlineCallbacks
    def get_pagination_rows(self, from_token, to_token, limit, key):
        to_key = to_token.events_key if to_token else None

        events, next_key = yield self.store.paginate_room_events(
            room_id=key,
            from_key=from_token.events_key,
            to_key=to_key,
            direction='b',
            limit=limit,
            with_feedback=True
        )

        next_token = from_token.copy_and_replace("events_key", next_key)

        defer.returnValue((events, next_token))


class PresenceStreamSource(object):
    SIGNAL_NAME = "PresenceStreamSource"

    def __init__(self, hs):
        self.hs = hs
        self.clock = hs.get_clock()

    def get_new_events_for_user(self, user, from_token, limit, key=None):
        from_key = int(from_token.presence_key)

        presence = self.hs.get_handlers().presence_handler
        cachemap = presence._user_cachemap

        # TODO(paul): limit, and filter by visibility
        updates = [(k, cachemap[k]) for k in cachemap
                   if from_key < cachemap[k].serial]

        if updates:
            clock = self.clock

            latest_serial = max([x[1].serial for x in updates])
            data = [x[1].make_event(user=x[0], clock=clock) for x in updates]

            end_token = from_token.copy_and_replace(
                "presence_key", latest_serial
            )
            return ((data, end_token))
        else:
            end_token = from_token.copy_and_replace(
                "presence_key", presence._user_cachemap_latest_serial
            )
            return (([], end_token))

    def get_keys_for_user(self, user):
        return defer.succeed([])

    def get_current_token_part(self):
        presence = self.hs.get_handlers().presence_handler
        return presence._user_cachemap_latest_serial


class EventSources(object):
    SOURCE_TYPES = [
        RoomEventSource,
        PresenceStreamSource,
    ]

    def __init__(self, hs):
        self.sources = [t(hs) for t in EventSources.SOURCE_TYPES]

    @staticmethod
    def create_token(events_key, presence_key):
        return StreamToken(events_key=events_key, presence_key=presence_key)

    @defer.inlineCallbacks
    def get_current_token(self):
        events_key = yield self.sources[0].get_current_token_part()
        token = EventSources.create_token(events_key, "0")
        defer.returnValue(token)


class StreamSource(object):
    def get_keys_for_user(self, user):
        raise NotImplementedError("get_keys_for_user")

    def get_new_events_for_user(self, user, from_token, limit, key=None):
        raise NotImplementedError("get_new_events_for_user")

    def get_current_token_part(self):
        raise NotImplementedError("get_current_token_part")


class PaginationSource(object):
    def get_pagination_rows(self, from_token, to_token, limit, key):
        raise NotImplementedError("get_rows")

