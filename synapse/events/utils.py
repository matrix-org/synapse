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

from synapse.api.constants import EventTypes
from . import EventBase

from frozendict import frozendict

import re

# Split strings on "." but not "\." This uses a negative lookbehind assertion for '\'
# (?<!stuff) matches if the current position in the string is not preceded
# by a match for 'stuff'.
# TODO: This is fast, but fails to handle "foo\\.bar" which should be treated as
#       the literal fields "foo\" and "bar" but will instead be treated as "foo\\.bar"
SPLIT_FIELD_REGEX = re.compile(r'(?<!\\)\.')


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
            "state_default",
            "ban",
            "kick",
            "redact",
        )
    elif event_type == EventTypes.Aliases:
        add_fields("aliases")
    elif event_type == EventTypes.RoomHistoryVisibility:
        add_fields("history_visibility")

    allowed_fields = {
        k: v
        for k, v in event_dict.items()
        if k in allowed_keys
    }

    allowed_fields["content"] = new_content

    allowed_fields["unsigned"] = {}

    if "age_ts" in event.unsigned:
        allowed_fields["unsigned"]["age_ts"] = event.unsigned["age_ts"]
    if "replaces_state" in event.unsigned:
        allowed_fields["unsigned"]["replaces_state"] = event.unsigned["replaces_state"]

    return type(event)(
        allowed_fields,
        internal_metadata_dict=event.internal_metadata.get_dict()
    )


def _copy_field(src, dst, field):
    """Copy the field in 'src' to 'dst'.

    For example, if src={"foo":{"bar":5}} and dst={}, and field=["foo","bar"]
    then dst={"foo":{"bar":5}}.

    Args:
        src(dict): The dict to read from.
        dst(dict): The dict to modify.
        field(list<str>): List of keys to drill down to in 'src'.
    """
    if len(field) == 0:  # this should be impossible
        return
    if len(field) == 1:  # common case e.g. 'origin_server_ts'
        if field[0] in src:
            dst[field[0]] = src[field[0]]
        return

    # Else is a nested field e.g. 'content.body'
    # Pop the last field as that's the key to move across and we need the
    # parent dict in order to access the data. Drill down to the right dict.
    key_to_move = field.pop(-1)
    sub_dict = src
    for sub_field in field:  # e.g. sub_field => "content"
        if sub_field in sub_dict and type(sub_dict[sub_field]) in [dict, frozendict]:
            sub_dict = sub_dict[sub_field]
        else:
            return

    if key_to_move not in sub_dict:
        return

    # Insert the key into the output dictionary, creating nested objects
    # as required. We couldn't do this any earlier or else we'd need to delete
    # the empty objects if the key didn't exist.
    sub_out_dict = dst
    for sub_field in field:
        sub_out_dict = sub_out_dict.setdefault(sub_field, {})
    sub_out_dict[key_to_move] = sub_dict[key_to_move]


def only_fields(dictionary, fields):
    """Return a new dict with only the fields in 'dictionary' which are present
    in 'fields'.

    If there are no event fields specified then all fields are included.
    The entries may include '.' charaters to indicate sub-fields.
    So ['content.body'] will include the 'body' field of the 'content' object.
    A literal '.' character in a field name may be escaped using a '\'.

    Args:
        dictionary(dict): The dictionary to read from.
        fields(list<str>): A list of fields to copy over. Only shallow refs are
        taken.
    Returns:
        dict: A new dictionary with only the given fields. If fields was empty,
        the same dictionary is returned.
    """
    if len(fields) == 0:
        return dictionary

    # for each field, convert it:
    # ["content.body.thing\.with\.dots"] => [["content", "body", "thing\.with\.dots"]]
    split_fields = [SPLIT_FIELD_REGEX.split(f) for f in fields]

    # for each element of the output array of arrays:
    # remove escaping so we can use the right key names.
    split_fields[:] = [
        [f.replace(r'\.', r'.') for f in field_array] for field_array in split_fields
    ]

    output = {}
    for field_array in split_fields:
        _copy_field(dictionary, output, field_array)
    return output


def format_event_raw(d):
    return d


def format_event_for_client_v1(d):
    d = format_event_for_client_v2(d)

    sender = d.get("sender")
    if sender is not None:
        d["user_id"] = sender

    copy_keys = (
        "age", "redacted_because", "replaces_state", "prev_content",
        "invite_room_state",
    )
    for key in copy_keys:
        if key in d["unsigned"]:
            d[key] = d["unsigned"][key]

    return d


def format_event_for_client_v2(d):
    drop_keys = (
        "auth_events", "prev_events", "hashes", "signatures", "depth",
        "origin", "prev_state",
    )
    for key in drop_keys:
        d.pop(key, None)
    return d


def format_event_for_client_v2_without_room_id(d):
    d = format_event_for_client_v2(d)
    d.pop("room_id", None)
    return d


def serialize_event(e, time_now_ms, as_client_event=True,
                    event_format=format_event_for_client_v1,
                    token_id=None, only_event_fields=None):
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
            e.unsigned["redacted_because"], time_now_ms,
            event_format=event_format
        )

    if token_id is not None:
        if token_id == getattr(e.internal_metadata, "token_id", None):
            txn_id = getattr(e.internal_metadata, "txn_id", None)
            if txn_id is not None:
                d["unsigned"]["transaction_id"] = txn_id

    if as_client_event:
        d = event_format(d)

    if only_event_fields:
        if (not isinstance(only_event_fields, list) or
                not all(isinstance(f, basestring) for f in only_event_fields)):
            raise TypeError("only_event_fields must be a list of strings")
        d = only_fields(d, only_event_fields)

    return d
