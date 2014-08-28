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

from synapse.types import StreamToken


class NullSource(object):
    """This event source never yields any events and its token remains at
    zero. It may be useful for unit-testing."""
    def __init__(self, hs):
        pass

    def get_new_events_for_user(self, user, from_token, limit):
        return defer.succeed(([], from_token))

    def get_current_token_part(self):
        return defer.succeed(0)

    def get_pagination_rows(self, user, pagination_config, key):
        return defer.succeed(([], pagination_config.from_token))


class RoomEventSource(object):
    def __init__(self, hs):
        self.store = hs.get_datastore()

    @defer.inlineCallbacks
    def get_new_events_for_user(self, user, from_token, limit):
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
    def get_pagination_rows(self, user, pagination_config, key):
        from_token = pagination_config.from_token
        to_token = pagination_config.to_token
        limit = pagination_config.limit
        direction = pagination_config.direction

        to_key = to_token.events_key if to_token else None

        events, next_key = yield self.store.paginate_room_events(
            room_id=key,
            from_key=from_token.events_key,
            to_key=to_key,
            direction=direction,
            limit=limit,
            with_feedback=True
        )

        next_token = from_token.copy_and_replace("events_key", next_key)

        defer.returnValue((events, next_token))


class PresenceSource(object):
    def __init__(self, hs):
        self.hs = hs
        self.clock = hs.get_clock()

    def get_new_events_for_user(self, user, from_token, limit):
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

    def get_current_token_part(self):
        presence = self.hs.get_handlers().presence_handler
        return presence._user_cachemap_latest_serial

    def get_pagination_rows(self, user, pagination_config, key):
        # TODO (erikj): Does this make sense? Ordering?

        from_token = pagination_config.from_token
        to_token = pagination_config.to_token

        from_key = int(from_token.presence_key)

        if to_token:
            to_key = int(to_token.presence_key)
        else:
            to_key = -1

        presence = self.hs.get_handlers().presence_handler
        cachemap = presence._user_cachemap

        # TODO(paul): limit, and filter by visibility
        updates = [(k, cachemap[k]) for k in cachemap
                   if to_key < cachemap[k].serial < from_key]

        if updates:
            clock = self.clock

            earliest_serial = max([x[1].serial for x in updates])
            data = [x[1].make_event(user=x[0], clock=clock) for x in updates]

            if to_token:
                next_token = to_token
            else:
                next_token = from_token

            next_token = next_token.copy_and_replace(
                "presence_key", earliest_serial
            )
            return ((data, next_token))
        else:
            if not to_token:
                to_token = from_token.copy_and_replace(
                    "presence_key", 0
                )
            return (([], to_token))


class EventSources(object):
    SOURCE_TYPES = {
        "room": RoomEventSource,
        "presence": PresenceSource,
    }

    def __init__(self, hs):
        self.sources = {
            name: cls(hs)
            for name, cls in EventSources.SOURCE_TYPES.items()
        }

    @staticmethod
    def create_token(events_key, presence_key):
        return StreamToken(events_key=events_key, presence_key=presence_key)

    @defer.inlineCallbacks
    def get_current_token(self):
        events_key = yield self.sources["room"].get_current_token_part()
        presence_key = yield self.sources["presence"].get_current_token_part()
        token = EventSources.create_token(events_key, presence_key)
        defer.returnValue(token)


class StreamSource(object):
    def get_new_events_for_user(self, user, from_token, limit):
        raise NotImplementedError("get_new_events_for_user")

    def get_current_token_part(self):
        raise NotImplementedError("get_current_token_part")

    def get_pagination_rows(self, user, pagination_config, key):
        raise NotImplementedError("get_rows")
