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

from synapse.api.constants import EventTypes
from . import EventBase


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
        "sender",
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
        "membership",
    ]

    new_content = {}

    def add_fields(*fields):
        for field in fields:
            if field in event.content:
                new_content[field] = event.content[field]

    if event_type == EventTypes.Member:
        add_fields("membership")
    elif event_type == EventTypes.Create:
        add_fields("creator")
    elif event_type == EventTypes.JoinRules:
        add_fields("join_rule")
    elif event_type == EventTypes.PowerLevels:
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
    elif event_type == EventTypes.Aliases:
        add_fields("aliases")

    allowed_fields = {
        k: v
        for k, v in event.get_dict().items()
        if k in allowed_keys
    }

    allowed_fields["content"] = new_content

    allowed_fields["unsigned"] = {}

    if "age_ts" in event.unsigned:
        allowed_fields["unsigned"]["age_ts"] = event.unsigned["age_ts"]

    return type(event)(allowed_fields)


def serialize_event(hs, e):
    # FIXME(erikj): To handle the case of presence events and the like
    if not isinstance(e, EventBase):
        return e

    # Should this strip out None's?
    d = {k: v for k, v in e.get_dict().items()}
    if "age_ts" in d["unsigned"]:
        now = int(hs.get_clock().time_msec())
        d["unsigned"]["age"] = now - d["unsigned"]["age_ts"]
        del d["unsigned"]["age_ts"]

    d["user_id"] = d.pop("sender", None)

    if "redacted_because" in e.unsigned:
        d["redacted_because"] = serialize_event(
            hs, e.unsigned["redacted_because"]
        )

        del d["unsigned"]["redacted_because"]

    if "redacted_by" in e.unsigned:
        d["redacted_by"] = e.unsigned["redacted_by"]
        del d["unsigned"]["redacted_by"]

    if "replaces_state" in e.unsigned:
        d["replaces_state"] = e.unsigned["replaces_state"]
        del d["unsigned"]["replaces_state"]

    if "prev_content" in e.unsigned:
        d["prev_content"] = e.unsigned["prev_content"]
        del d["unsigned"]["prev_content"]

    del d["auth_events"]
    del d["prev_events"]
    del d["hashes"]
    del d["signatures"]
    d.pop("depth", None)
    d.pop("unsigned", None)
    d.pop("origin", None)

    return d
