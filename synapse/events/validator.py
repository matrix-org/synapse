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

from synapse.api.constants import MAX_ALIAS_LENGTH, EventTypes, Membership
from synapse.api.errors import Codes, SynapseError
from synapse.api.room_versions import EventFormatVersions
from synapse.types import EventID, RoomID, UserID


class EventValidator(object):
    def validate_new(self, event):
        """Validates the event has roughly the right format

        Args:
            event (FrozenEvent)
        """
        self.validate_builder(event)

        if event.format_version == EventFormatVersions.V1:
            EventID.from_string(event.event_id)

        required = [
            "auth_events",
            "content",
            "hashes",
            "origin",
            "prev_events",
            "sender",
            "type",
        ]

        for k in required:
            if not hasattr(event, k):
                raise SynapseError(400, "Event does not have key %s" % (k,))

        # Check that the following keys have string values
        event_strings = ["origin"]

        for s in event_strings:
            if not isinstance(getattr(event, s), string_types):
                raise SynapseError(400, "'%s' not a string type" % (s,))

        if event.type == EventTypes.Aliases:
            if "aliases" in event.content:
                for alias in event.content["aliases"]:
                    if len(alias) > MAX_ALIAS_LENGTH:
                        raise SynapseError(
                            400,
                            (
                                "Can't create aliases longer than"
                                " %d characters" % (MAX_ALIAS_LENGTH,)
                            ),
                            Codes.INVALID_PARAM,
                        )

    def validate_builder(self, event):
        """Validates that the builder/event has roughly the right format. Only
        checks values that we expect a proto event to have, rather than all the
        fields an event would have

        Args:
            event (EventBuilder|FrozenEvent)
        """

        strings = ["room_id", "sender", "type"]

        if hasattr(event, "state_key"):
            strings.append("state_key")

        for s in strings:
            if not isinstance(getattr(event, s), string_types):
                raise SynapseError(400, "Not '%s' a string type" % (s,))

        RoomID.from_string(event.room_id)
        UserID.from_string(event.sender)

        if event.type == EventTypes.Message:
            strings = ["body", "msgtype"]

            self._ensure_strings(event.content, strings)

        elif event.type == EventTypes.Topic:
            self._ensure_strings(event.content, ["topic"])

        elif event.type == EventTypes.Name:
            self._ensure_strings(event.content, ["name"])

        elif event.type == EventTypes.Member:
            if "membership" not in event.content:
                raise SynapseError(400, "Content has not membership key")

            if event.content["membership"] not in Membership.LIST:
                raise SynapseError(400, "Invalid membership key")

    def _ensure_strings(self, d, keys):
        for s in keys:
            if s not in d:
                raise SynapseError(400, "'%s' not in content" % (s,))
            if not isinstance(d[s], string_types):
                raise SynapseError(400, "'%s' not a string type" % (s,))
