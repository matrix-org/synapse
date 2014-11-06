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

from .room import (
    RoomMemberEvent, RoomJoinRulesEvent, RoomPowerLevelsEvent,
    RoomAliasesEvent, RoomCreateEvent,
)

def prune_event(event):
    """ Prunes the given event of all keys we don't know about or think could
    potentially be dodgy.

    This is used when we "redact" an event. We want to remove all fields that
    the user has specified, but we do want to keep necessary information like
    type, state_key etc.
    """
    return _prune_event_or_pdu(event.type, event)

def prune_pdu(pdu):
    """Removes keys that contain unrestricted and non-essential data from a PDU
    """
    return _prune_event_or_pdu(pdu.type, pdu)

def _prune_event_or_pdu(event_type, event):
    # Remove all extraneous fields.
    event.unrecognized_keys = {}

    new_content = {}

    def add_fields(*fields):
        for field in fields:
            if field in event.content:
                new_content[field] = event.content[field]

    if event_type == RoomMemberEvent.TYPE:
        add_fields("membership")
    elif event_type == RoomCreateEvent.TYPE:
        add_fields("creator")
    elif event_type == RoomJoinRulesEvent.TYPE:
        add_fields("join_rule")
    elif event_type == RoomPowerLevelsEvent.TYPE:
        add_fields(
            "users",
            "users_default",
            "events",
            "events_default",
            "events_default",
            "state_default",
            "ban",
            "kick",
            "redact",
        )
    elif event_type == RoomAliasesEvent.TYPE:
        add_fields("aliases")

    event.content = new_content

    return event
