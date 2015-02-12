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

    event_dict = event.get_dict()

    new_content = {}

    def add_fields(*fields):
        for field in fields:
            if field in event.content:
                new_content[field] = event_dict["content"][field]

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
        for k, v in event_dict.items()
        if k in allowed_keys
    }

    allowed_fields["content"] = new_content

    allowed_fields["unsigned"] = {}

    if "age_ts" in event.unsigned:
        allowed_fields["unsigned"]["age_ts"] = event.unsigned["age_ts"]

    return type(event)(
        allowed_fields,
        internal_metadata_dict=event.internal_metadata.get_dict()
    )


def format_event_raw(d):
    return d


def format_event_for_client_v1(d):
    d["user_id"] = d.pop("sender", None)

    move_keys = ("age", "redacted_because", "replaces_state", "prev_content")
    for key in move_keys:
        if key in d["unsigned"]:
            d[key] = d["unsigned"][key]

    drop_keys = (
        "auth_events", "prev_events", "hashes", "signatures", "depth",
        "unsigned", "origin", "prev_state"
    )
    for key in drop_keys:
        d.pop(key, None)
    return d


def format_event_for_client_v2(d):
    drop_keys = (
        "auth_events", "prev_events", "hashes", "signatures", "depth",
        "origin", "prev_state",
    )
    for key in drop_keys:
        d.pop(key, None)
    return d


def format_event_for_client_v2_without_event_id(d):
    d = format_event_for_client_v2(d)
    d.pop("room_id", None)
    d.pop("event_id", None)
    return d


def serialize_event(e, time_now_ms, as_client_event=True,
                    event_format=format_event_for_client_v1,
                    token_id=None):
    # FIXME(erikj): To handle the case of presence events and the like
    if not isinstance(e, EventBase):
        return e

    time_now_ms = int(time_now_ms)

    # Should this strip out None's?
    d = {k: v for k, v in e.get_dict().items()}

    if "age_ts" in d["unsigned"]:
        d["unsigned"]["age"] = time_now_ms - d["unsigned"]["age_ts"]
        del d["unsigned"]["age_ts"]

    if "redacted_because" in e.unsigned:
        d["unsigned"]["redacted_because"] = serialize_event(
            e.unsigned["redacted_because"], time_now_ms
        )

    if token_id is not None:
        if token_id == getattr(e.internal_metadata, "token_id", None):
            txn_id = getattr(e.internal_metadata, "txn_id", None)
            if txn_id is not None:
                d["unsigned"]["transaction_id"] = txn_id

    if as_client_event:
        return event_format(d)
    else:
        return d
