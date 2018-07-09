# -*- coding: utf-8 -*-
# Copyright 2014-2016 OpenMarket Ltd
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

from six import string_types

from synapse.api.constants import EventTypes, Membership
from synapse.api.errors import SynapseError
from synapse.types import EventID, RoomID, UserID


class EventValidator(object):

    def validate(self, event):
        EventID.from_string(event.event_id)
        RoomID.from_string(event.room_id)

        required = [
            # "auth_events",
            "content",
            # "hashes",
            "origin",
            # "prev_events",
            "sender",
            "type",
        ]

        for k in required:
            if not hasattr(event, k):
                raise SynapseError(400, "Event does not have key %s" % (k,))

        # Check that the following keys have string values
        strings = [
            "origin",
            "sender",
            "type",
        ]

        if hasattr(event, "state_key"):
            strings.append("state_key")

        for s in strings:
            if not isinstance(getattr(event, s), string_types):
                raise SynapseError(400, "Not '%s' a string type" % (s,))

        if event.type == EventTypes.Member:
            if "membership" not in event.content:
                raise SynapseError(400, "Content has not membership key")

            if event.content["membership"] not in Membership.LIST:
                raise SynapseError(400, "Invalid membership key")

        # Check that the following keys have dictionary values
        # TODO

        # Check that the following keys have the correct format for DAGs
        # TODO

    def validate_new(self, event):
        self.validate(event)

        UserID.from_string(event.sender)

        if event.type == EventTypes.Message:
            strings = [
                "body",
                "msgtype",
            ]

            self._ensure_strings(event.content, strings)

        elif event.type == EventTypes.Topic:
            self._ensure_strings(event.content, ["topic"])

        elif event.type == EventTypes.Name:
            self._ensure_strings(event.content, ["name"])

    def _ensure_strings(self, d, keys):
        for s in keys:
            if s not in d:
                raise SynapseError(400, "'%s' not in content" % (s,))
            if not isinstance(d[s], string_types):
                raise SynapseError(400, "Not '%s' a string type" % (s,))
