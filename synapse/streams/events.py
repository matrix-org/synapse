# -*- coding: utf-8 -*-
# Copyright 2014, 2015 OpenMarket Ltd
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

from synapse.handlers.presence import PresenceEventSource
from synapse.handlers.room import RoomEventSource
from synapse.handlers.typing import TypingNotificationEventSource


class NullSource(object):
    """This event source never yields any events and its token remains at
    zero. It may be useful for unit-testing."""
    def __init__(self, hs):
        pass

    def get_new_events_for_user(self, user, from_key, limit):
        return defer.succeed(([], from_key))

    def get_current_key(self):
        return defer.succeed(0)

    def get_pagination_rows(self, user, pagination_config, key):
        return defer.succeed(([], pagination_config.from_key))


class EventSources(object):
    SOURCE_TYPES = {
        "room": RoomEventSource,
        "presence": PresenceEventSource,
        "typing": TypingNotificationEventSource,
    }

    def __init__(self, hs):
        self.sources = {
            name: cls(hs)
            for name, cls in EventSources.SOURCE_TYPES.items()
        }

    @defer.inlineCallbacks
    def get_current_token(self):
        token = StreamToken(
            room_key=(
                yield self.sources["room"].get_current_key()
            ),
            presence_key=(
                yield self.sources["presence"].get_current_key()
            ),
            typing_key=(
                yield self.sources["typing"].get_current_key()
            )
        )
        defer.returnValue(token)


class StreamSource(object):
    def get_new_events_for_user(self, user, from_key, limit):
        """from_key is the key within this event source."""
        raise NotImplementedError("get_new_events_for_user")

    def get_current_key(self):
        raise NotImplementedError("get_current_key")

    def get_pagination_rows(self, user, pagination_config, key):
        raise NotImplementedError("get_rows")
