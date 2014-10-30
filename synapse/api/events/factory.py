# -*- coding: utf-8 -*-
# Copyright 2014 OpenMarket Ltd
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

from synapse.api.events.room import (
    RoomTopicEvent, MessageEvent, RoomMemberEvent, FeedbackEvent,
    InviteJoinEvent, RoomConfigEvent, RoomNameEvent, GenericEvent,
    RoomPowerLevelsEvent, RoomJoinRulesEvent, RoomOpsPowerLevelsEvent,
    RoomCreateEvent, RoomAddStateLevelEvent, RoomSendEventLevelEvent,
    RoomRedactionEvent,
)

from synapse.types import EventID

from synapse.util.stringutils import random_string


class EventFactory(object):

    _event_classes = [
        RoomTopicEvent,
        RoomNameEvent,
        MessageEvent,
        RoomMemberEvent,
        FeedbackEvent,
        InviteJoinEvent,
        RoomConfigEvent,
        RoomPowerLevelsEvent,
        RoomJoinRulesEvent,
        RoomCreateEvent,
        RoomAddStateLevelEvent,
        RoomSendEventLevelEvent,
        RoomOpsPowerLevelsEvent,
        RoomRedactionEvent,
    ]

    def __init__(self, hs):
        self._event_list = {}  # dict of TYPE to event class
        for event_class in EventFactory._event_classes:
            self._event_list[event_class.TYPE] = event_class

        self.clock = hs.get_clock()
        self.hs = hs

        self.event_id_count = 0

    def create_event_id(self):
        i = str(self.event_id_count)
        self.event_id_count += 1

        local_part = str(int(self.clock.time())) + i + random_string(5)

        e_id = EventID.create_local(local_part, self.hs)

        return e_id.to_string()

    def create_event(self, etype=None, **kwargs):
        kwargs["type"] = etype
        if "event_id" not in kwargs:
            kwargs["event_id"] = self.create_event_id()

        if "origin_server_ts" not in kwargs:
            kwargs["origin_server_ts"] = int(self.clock.time_msec())

        # The "age" key is a delta timestamp that should be converted into an
        # absolute timestamp the minute we see it.
        if "age" in kwargs:
            kwargs["age_ts"] = int(self.clock.time_msec()) - int(kwargs["age"])
            del kwargs["age"]
        elif "age_ts" not in kwargs:
            kwargs["age_ts"] = int(self.clock.time_msec())

        if etype in self._event_list:
            handler = self._event_list[etype]
        else:
            handler = GenericEvent

        return handler(**kwargs)
