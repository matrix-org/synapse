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
    """ Returns a pruned version of the given event, which removes all keys we
    don't know about or think could potentially be dodgy.

    This is used when we "redact" an event. We want to remove all fields that
    the user has specified, but we do want to keep necessary information like
    type, state_key etc.
    """
    event_type = event.type

    allowed_keys = [
        "event_id",
        "user_id",
        "room_id",
        "hashes",
        "signatures",
        "content",
        "type",
        "state_key",
        "depth",
        "prev_events",
        "prev_state",
        "auth_events",
        "origin",
        "origin_server_ts",
    ]

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

    allowed_fields = {
        k: v
        for k, v in event.get_full_dict().items()
        if k in allowed_keys
    }

    allowed_fields["content"] = new_content

    return type(event)(**allowed_fields)
