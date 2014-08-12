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
from synapse.api.events.room import (
    RoomTopicEvent, MessageEvent, RoomMemberEvent, FeedbackEvent,
    InviteJoinEvent, RoomConfigEvent
)

from synapse.util.stringutils import random_string


class EventFactory(object):

    _event_classes = [
        RoomTopicEvent,
        MessageEvent,
        RoomMemberEvent,
        FeedbackEvent,
        InviteJoinEvent,
        RoomConfigEvent
    ]

    def __init__(self):
        self._event_list = {}  # dict of TYPE to event class
        for event_class in EventFactory._event_classes:
            self._event_list[event_class.TYPE] = event_class

    def create_event(self, etype=None, **kwargs):
        kwargs["type"] = etype
        if "event_id" not in kwargs:
            kwargs["event_id"] = random_string(10)

        try:
            handler = self._event_list[etype]
        except KeyError:  # unknown event type
            # TODO allow custom event types.
            raise NotImplementedError("Unknown etype=%s" % etype)

        return handler(**kwargs)
