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

from typing import Union

from synapse.api.constants import MAX_ALIAS_LENGTH, EventTypes, Membership
from synapse.api.errors import Codes, SynapseError
from synapse.api.room_versions import EventFormatVersions
from synapse.config.homeserver import HomeServerConfig
from synapse.events import EventBase
from synapse.events.builder import EventBuilder
from synapse.events.utils import validate_canonicaljson
from synapse.federation.federation_server import server_matches_acl_event
from synapse.types import EventID, RoomID, UserID


class EventValidator:
    def validate_new(self, event: EventBase, config: HomeServerConfig):
        """Validates the event has roughly the right format

        Args:
            event: The event to validate.
            config: The homeserver's configuration.
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
            if not isinstance(getattr(event, s), str):
                raise SynapseError(400, "'%s' not a string type" % (s,))

        # Depending on the room version, ensure the data is spec compliant JSON.
        if event.room_version.strict_canonicaljson:
            # Note that only the client controlled portion of the event is
            # checked, since we trust the portions of the event we created.
            validate_canonicaljson(event.content)

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

        if event.type == EventTypes.Retention:
            self._validate_retention(event)

        if event.type == EventTypes.ServerACL:
            if not server_matches_acl_event(config.server_name, event):
                raise SynapseError(
                    400, "Can't create an ACL event that denies the local server"
                )

    def _validate_retention(self, event: EventBase):
        """Checks that an event that defines the retention policy for a room respects the
        format enforced by the spec.

        Args:
            event: The event to validate.
        """
        if not event.is_state():
            raise SynapseError(code=400, msg="must be a state event")

        min_lifetime = event.content.get("min_lifetime")
        max_lifetime = event.content.get("max_lifetime")

        if min_lifetime is not None:
            if not isinstance(min_lifetime, int):
                raise SynapseError(
                    code=400,
                    msg="'min_lifetime' must be an integer",
                    errcode=Codes.BAD_JSON,
                )

        if max_lifetime is not None:
            if not isinstance(max_lifetime, int):
                raise SynapseError(
                    code=400,
                    msg="'max_lifetime' must be an integer",
                    errcode=Codes.BAD_JSON,
                )

        if (
            min_lifetime is not None
            and max_lifetime is not None
            and min_lifetime > max_lifetime
        ):
            raise SynapseError(
                code=400,
                msg="'min_lifetime' can't be greater than 'max_lifetime",
                errcode=Codes.BAD_JSON,
            )

    def validate_builder(self, event: Union[EventBase, EventBuilder]):
        """Validates that the builder/event has roughly the right format. Only
        checks values that we expect a proto event to have, rather than all the
        fields an event would have
        """

        strings = ["room_id", "sender", "type"]

        if hasattr(event, "state_key"):
            strings.append("state_key")

        for s in strings:
            if not isinstance(getattr(event, s), str):
                raise SynapseError(400, "Not '%s' a string type" % (s,))

        RoomID.from_string(event.room_id)
        UserID.from_string(event.sender)

        if event.type == EventTypes.Message:
            strings = ["body", "msgtype"]

            self._ensure_strings(event.content, strings)

        elif event.type == EventTypes.Topic:
            self._ensure_strings(event.content, ["topic"])
            self._ensure_state_event(event)
        elif event.type == EventTypes.Name:
            self._ensure_strings(event.content, ["name"])
            self._ensure_state_event(event)
        elif event.type == EventTypes.Member:
            if "membership" not in event.content:
                raise SynapseError(400, "Content has not membership key")

            if event.content["membership"] not in Membership.LIST:
                raise SynapseError(400, "Invalid membership key")

            self._ensure_state_event(event)
        elif event.type == EventTypes.Tombstone:
            if "replacement_room" not in event.content:
                raise SynapseError(400, "Content has no replacement_room key")

            if event.content["replacement_room"] == event.room_id:
                raise SynapseError(
                    400, "Tombstone cannot reference the room it was sent in"
                )

            self._ensure_state_event(event)

    def _ensure_strings(self, d, keys):
        for s in keys:
            if s not in d:
                raise SynapseError(400, "'%s' not in content" % (s,))
            if not isinstance(d[s], str):
                raise SynapseError(400, "'%s' not a string type" % (s,))

    def _ensure_state_event(self, event):
        if not event.is_state():
            raise SynapseError(400, "'%s' must be state events" % (event.type,))
