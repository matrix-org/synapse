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

from synapse.types import EventID, RoomID, UserID
from synapse.api.errors import SynapseError


class EventValidator(object):

    def validate(self, event):
        EventID.from_string(event.event_id)
        RoomID.from_string(event.room_id)

        hasattr(event, "auth_events")
        hasattr(event, "content")
        hasattr(event, "hashes")
        hasattr(event, "origin")
        hasattr(event, "prev_events")
        hasattr(event, "prev_events")
        hasattr(event, "sender")
        hasattr(event, "type")

        # Check that the following keys have string values
        strings = [
            "origin",
            "sender",
            "type",
        ]

        if hasattr(event, "state_key"):
            strings.append("state_key")

        for s in strings:
            if not isinstance(getattr(event, s), basestring):
                raise SynapseError(400, "Not '%s' a string type" % (s,))

        # Check that the following keys have dictionary values
        # TODO

        # Check that the following keys have the correct format for DAGs
        # TODO

    def validate_new(self, event):
        self.validate(event)

        UserID.from_string(event.sender)
