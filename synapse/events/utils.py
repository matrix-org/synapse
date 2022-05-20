# Copyright 2014-2016 OpenMarket Ltd
# Copyright 2021 The Matrix.org Foundation C.I.C.
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
import collections.abc
import re
from typing import (
    TYPE_CHECKING,
    Any,
    Callable,
    Dict,
    Iterable,
    List,
    Mapping,
    MutableMapping,
    Optional,
    Union,
)

import attr

from synapse.api.constants import EventContentFields, EventTypes, RelationTypes
from synapse.api.errors import Codes, SynapseError
from synapse.api.room_versions import RoomVersion
from synapse.types import JsonDict
from synapse.util.frozenutils import unfreeze

from . import EventBase

if TYPE_CHECKING:
    from synapse.handlers.relations import BundledAggregations


# Split strings on "." but not "\." This uses a negative lookbehind assertion for '\'
# (?<!stuff) matches if the current position in the string is not preceded
# by a match for 'stuff'.
# TODO: This is fast, but fails to handle "foo\\.bar" which should be treated as
#       the literal fields "foo\" and "bar" but will instead be treated as "foo\\.bar"
SPLIT_FIELD_REGEX = re.compile(r"(?<!\\)\.")

CANONICALJSON_MAX_INT = (2**53) - 1
CANONICALJSON_MIN_INT = -CANONICALJSON_MAX_INT


def prune_event(event: EventBase) -> EventBase:
    """Returns a pruned version of the given event, which removes all keys we
    don't know about or think could potentially be dodgy.

    This is used when we "redact" an event. We want to remove all fields that
    the user has specified, but we do want to keep necessary information like
    type, state_key etc.
    """
    pruned_event_dict = prune_event_dict(event.room_version, event.get_dict())

    from . import make_event_from_dict

    pruned_event = make_event_from_dict(
        pruned_event_dict, event.room_version, event.internal_metadata.get_dict()
    )

    # copy the internal fields
    pruned_event.internal_metadata.stream_ordering = (
        event.internal_metadata.stream_ordering
    )

    pruned_event.internal_metadata.outlier = event.internal_metadata.outlier

    # Mark the event as redacted
    pruned_event.internal_metadata.redacted = True

    return pruned_event


def prune_event_dict(room_version: RoomVersion, event_dict: JsonDict) -> JsonDict:
    """Redacts the event_dict in the same way as `prune_event`, except it
    operates on dicts rather than event objects

    Returns:
        A copy of the pruned event dict
    """

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
        "auth_events",
        "origin",
        "origin_server_ts",
    ]

    # Room versions from before MSC2176 had additional allowed keys.
    if not room_version.msc2176_redaction_rules:
        allowed_keys.extend(["prev_state", "membership"])

    event_type = event_dict["type"]

    new_content = {}

    def add_fields(*fields: str) -> None:
        for field in fields:
            if field in event_dict["content"]:
                new_content[field] = event_dict["content"][field]

    if event_type == EventTypes.Member:
        add_fields("membership")
        if room_version.msc3375_redaction_rules:
            add_fields(EventContentFields.AUTHORISING_USER)
    elif event_type == EventTypes.Create:
        # MSC2176 rules state that create events cannot be redacted.
        if room_version.msc2176_redaction_rules:
            return event_dict

        add_fields("creator")
    elif event_type == EventTypes.JoinRules:
        add_fields("join_rule")
        if room_version.msc3083_join_rules:
            add_fields("allow")
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

        if room_version.msc2176_redaction_rules:
            add_fields("invite")

        if room_version.msc2716_historical:
            add_fields("historical")

    elif event_type == EventTypes.Aliases and room_version.special_case_aliases_auth:
        add_fields("aliases")
    elif event_type == EventTypes.RoomHistoryVisibility:
        add_fields("history_visibility")
    elif event_type == EventTypes.Redaction and room_version.msc2176_redaction_rules:
        add_fields("redacts")
    elif room_version.msc2716_redactions and event_type == EventTypes.MSC2716_INSERTION:
        add_fields(EventContentFields.MSC2716_NEXT_BATCH_ID)
    elif room_version.msc2716_redactions and event_type == EventTypes.MSC2716_BATCH:
        add_fields(EventContentFields.MSC2716_BATCH_ID)
    elif room_version.msc2716_redactions and event_type == EventTypes.MSC2716_MARKER:
        add_fields(EventContentFields.MSC2716_MARKER_INSERTION)

    allowed_fields = {k: v for k, v in event_dict.items() if k in allowed_keys}

    allowed_fields["content"] = new_content

    unsigned: JsonDict = {}
    allowed_fields["unsigned"] = unsigned

    event_unsigned = event_dict.get("unsigned", {})

    if "age_ts" in event_unsigned:
        unsigned["age_ts"] = event_unsigned["age_ts"]
    if "replaces_state" in event_unsigned:
        unsigned["replaces_state"] = event_unsigned["replaces_state"]

    return allowed_fields


def _copy_field(src: JsonDict, dst: JsonDict, field: List[str]) -> None:
    """Copy the field in 'src' to 'dst'.

    For example, if src={"foo":{"bar":5}} and dst={}, and field=["foo","bar"]
    then dst={"foo":{"bar":5}}.

    Args:
        src: The dict to read from.
        dst: The dict to modify.
        field: List of keys to drill down to in 'src'.
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
        if sub_field in sub_dict and isinstance(
            sub_dict[sub_field], collections.abc.Mapping
        ):
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


def only_fields(dictionary: JsonDict, fields: List[str]) -> JsonDict:
    """Return a new dict with only the fields in 'dictionary' which are present
    in 'fields'.

    If there are no event fields specified then all fields are included.
    The entries may include '.' characters to indicate sub-fields.
    So ['content.body'] will include the 'body' field of the 'content' object.
    A literal '.' character in a field name may be escaped using a '\'.

    Args:
        dictionary: The dictionary to read from.
        fields: A list of fields to copy over. Only shallow refs are
        taken.
    Returns:
        A new dictionary with only the given fields. If fields was empty,
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
        [f.replace(r"\.", r".") for f in field_array] for field_array in split_fields
    ]

    output: JsonDict = {}
    for field_array in split_fields:
        _copy_field(dictionary, output, field_array)
    return output


def format_event_raw(d: JsonDict) -> JsonDict:
    return d


def format_event_for_client_v1(d: JsonDict) -> JsonDict:
    d = format_event_for_client_v2(d)

    sender = d.get("sender")
    if sender is not None:
        d["user_id"] = sender

    copy_keys = (
        "age",
        "redacted_because",
        "replaces_state",
        "prev_content",
        "invite_room_state",
        "knock_room_state",
    )
    for key in copy_keys:
        if key in d["unsigned"]:
            d[key] = d["unsigned"][key]

    return d


def format_event_for_client_v2(d: JsonDict) -> JsonDict:
    drop_keys = (
        "auth_events",
        "prev_events",
        "hashes",
        "signatures",
        "depth",
        "origin",
        "prev_state",
    )
    for key in drop_keys:
        d.pop(key, None)
    return d


def format_event_for_client_v2_without_room_id(d: JsonDict) -> JsonDict:
    d = format_event_for_client_v2(d)
    d.pop("room_id", None)
    return d


@attr.s(slots=True, frozen=True, auto_attribs=True)
class SerializeEventConfig:
    as_client_event: bool = True
    # Function to convert from federation format to client format
    event_format: Callable[[JsonDict], JsonDict] = format_event_for_client_v1
    # ID of the user's auth token - used for namespacing of transaction IDs
    token_id: Optional[int] = None
    # List of event fields to include. If empty, all fields will be returned.
    only_event_fields: Optional[List[str]] = None
    # Some events can have stripped room state stored in the `unsigned` field.
    # This is required for invite and knock functionality. If this option is
    # False, that state will be removed from the event before it is returned.
    # Otherwise, it will be kept.
    include_stripped_room_state: bool = False


_DEFAULT_SERIALIZE_EVENT_CONFIG = SerializeEventConfig()


def serialize_event(
    e: Union[JsonDict, EventBase],
    time_now_ms: int,
    *,
    config: SerializeEventConfig = _DEFAULT_SERIALIZE_EVENT_CONFIG,
) -> JsonDict:
    """Serialize event for clients

    Args:
        e
        time_now_ms
        config: Event serialization config

    Returns:
        The serialized event dictionary.
    """

    # FIXME(erikj): To handle the case of presence events and the like
    if not isinstance(e, EventBase):
        return e

    time_now_ms = int(time_now_ms)

    # Should this strip out None's?
    d = {k: v for k, v in e.get_dict().items()}

    d["event_id"] = e.event_id

    if "age_ts" in d["unsigned"]:
        d["unsigned"]["age"] = time_now_ms - d["unsigned"]["age_ts"]
        del d["unsigned"]["age_ts"]

    if "redacted_because" in e.unsigned:
        d["unsigned"]["redacted_because"] = serialize_event(
            e.unsigned["redacted_because"], time_now_ms, config=config
        )

    if config.token_id is not None:
        if config.token_id == getattr(e.internal_metadata, "token_id", None):
            txn_id = getattr(e.internal_metadata, "txn_id", None)
            if txn_id is not None:
                d["unsigned"]["transaction_id"] = txn_id

    # invite_room_state and knock_room_state are a list of stripped room state events
    # that are meant to provide metadata about a room to an invitee/knocker. They are
    # intended to only be included in specific circumstances, such as down sync, and
    # should not be included in any other case.
    if not config.include_stripped_room_state:
        d["unsigned"].pop("invite_room_state", None)
        d["unsigned"].pop("knock_room_state", None)

    if config.as_client_event:
        d = config.event_format(d)

    only_event_fields = config.only_event_fields
    if only_event_fields:
        if not isinstance(only_event_fields, list) or not all(
            isinstance(f, str) for f in only_event_fields
        ):
            raise TypeError("only_event_fields must be a list of strings")
        d = only_fields(d, only_event_fields)

    return d


class EventClientSerializer:
    """Serializes events that are to be sent to clients.

    This is used for bundling extra information with any events to be sent to
    clients.
    """

    def serialize_event(
        self,
        event: Union[JsonDict, EventBase],
        time_now: int,
        *,
        config: SerializeEventConfig = _DEFAULT_SERIALIZE_EVENT_CONFIG,
        bundle_aggregations: Optional[Dict[str, "BundledAggregations"]] = None,
        apply_edits: bool = True,
    ) -> JsonDict:
        """Serializes a single event.

        Args:
            event: The event being serialized.
            time_now: The current time in milliseconds
            config: Event serialization config
            bundle_aggregations: A map from event_id to the aggregations to be bundled
               into the event.
            apply_edits: Whether the content of the event should be modified to reflect
               any replacement in `bundle_aggregations[<event_id>].replace`.
        Returns:
            The serialized event
        """
        # To handle the case of presence events and the like
        if not isinstance(event, EventBase):
            return event

        serialized_event = serialize_event(event, time_now, config=config)

        # Check if there are any bundled aggregations to include with the event.
        if bundle_aggregations:
            if event.event_id in bundle_aggregations:
                self._inject_bundled_aggregations(
                    event,
                    time_now,
                    config,
                    bundle_aggregations,
                    serialized_event,
                    apply_edits=apply_edits,
                )

        return serialized_event

    def _apply_edit(
        self, orig_event: EventBase, serialized_event: JsonDict, edit: EventBase
    ) -> None:
        """Replace the content, preserving existing relations of the serialized event.

        Args:
            orig_event: The original event.
            serialized_event: The original event, serialized. This is modified.
            edit: The event which edits the above.
        """

        # Ensure we take copies of the edit content, otherwise we risk modifying
        # the original event.
        edit_content = edit.content.copy()

        # Unfreeze the event content if necessary, so that we may modify it below
        edit_content = unfreeze(edit_content)
        serialized_event["content"] = edit_content.get("m.new_content", {})

        # Check for existing relations
        relates_to = orig_event.content.get("m.relates_to")
        if relates_to:
            # Keep the relations, ensuring we use a dict copy of the original
            serialized_event["content"]["m.relates_to"] = relates_to.copy()
        else:
            serialized_event["content"].pop("m.relates_to", None)

    def _inject_bundled_aggregations(
        self,
        event: EventBase,
        time_now: int,
        config: SerializeEventConfig,
        bundled_aggregations: Dict[str, "BundledAggregations"],
        serialized_event: JsonDict,
        apply_edits: bool,
    ) -> None:
        """Potentially injects bundled aggregations into the unsigned portion of the serialized event.

        Args:
            event: The event being serialized.
            time_now: The current time in milliseconds
            config: Event serialization config
            bundled_aggregations: Bundled aggregations to be injected.
                A map from event_id to aggregation data. Must contain at least an
                entry for `event`.

                While serializing the bundled aggregations this map may be searched
                again for additional events in a recursive manner.
            serialized_event: The serialized event which may be modified.
            apply_edits: Whether the content of the event should be modified to reflect
               any replacement in `aggregations.replace`.
        """

        # We have already checked that aggregations exist for this event.
        event_aggregations = bundled_aggregations[event.event_id]

        # The JSON dictionary to be added under the unsigned property of the event
        # being serialized.
        serialized_aggregations = {}

        if event_aggregations.annotations:
            serialized_aggregations[
                RelationTypes.ANNOTATION
            ] = event_aggregations.annotations

        if event_aggregations.references:
            serialized_aggregations[
                RelationTypes.REFERENCE
            ] = event_aggregations.references

        if event_aggregations.replace:
            # If there is an edit, optionally apply it to the event.
            edit = event_aggregations.replace
            if apply_edits:
                self._apply_edit(event, serialized_event, edit)

            # Include information about it in the relations dict.
            serialized_aggregations[RelationTypes.REPLACE] = {
                "event_id": edit.event_id,
                "origin_server_ts": edit.origin_server_ts,
                "sender": edit.sender,
            }

        # Include any threaded replies to this event.
        if event_aggregations.thread:
            thread = event_aggregations.thread

            serialized_latest_event = self.serialize_event(
                thread.latest_event,
                time_now,
                config=config,
                bundle_aggregations=bundled_aggregations,
            )

            thread_summary = {
                "latest_event": serialized_latest_event,
                "count": thread.count,
                "current_user_participated": thread.current_user_participated,
            }
            serialized_aggregations[RelationTypes.THREAD] = thread_summary

        # Include the bundled aggregations in the event.
        if serialized_aggregations:
            # There is likely already an "unsigned" field, but a filter might
            # have stripped it off (via the event_fields option). The server is
            # allowed to return additional fields, so add it back.
            serialized_event.setdefault("unsigned", {}).setdefault(
                "m.relations", {}
            ).update(serialized_aggregations)

    def serialize_events(
        self,
        events: Iterable[Union[JsonDict, EventBase]],
        time_now: int,
        *,
        config: SerializeEventConfig = _DEFAULT_SERIALIZE_EVENT_CONFIG,
        bundle_aggregations: Optional[Dict[str, "BundledAggregations"]] = None,
    ) -> List[JsonDict]:
        """Serializes multiple events.

        Args:
            event
            time_now: The current time in milliseconds
            config: Event serialization config
            bundle_aggregations: Whether to include the bundled aggregations for this
                event. Only applies to non-state events. (State events never include
                bundled aggregations.)

        Returns:
            The list of serialized events
        """
        return [
            self.serialize_event(
                event,
                time_now,
                config=config,
                bundle_aggregations=bundle_aggregations,
            )
            for event in events
        ]


_PowerLevel = Union[str, int]


def copy_and_fixup_power_levels_contents(
    old_power_levels: Mapping[str, Union[_PowerLevel, Mapping[str, _PowerLevel]]]
) -> Dict[str, Union[int, Dict[str, int]]]:
    """Copy the content of a power_levels event, unfreezing frozendicts along the way.

    We accept as input power level values which are strings, provided they represent an
    integer, e.g. `"`100"` instead of 100. Such strings are converted to integers
    in the returned dictionary (hence "fixup" in the function name).

    Note that future room versions will outlaw such stringy power levels (see
    https://github.com/matrix-org/matrix-spec/issues/853).

    Raises:
        TypeError if the input does not look like a valid power levels event content
    """
    if not isinstance(old_power_levels, collections.abc.Mapping):
        raise TypeError("Not a valid power-levels content: %r" % (old_power_levels,))

    power_levels: Dict[str, Union[int, Dict[str, int]]] = {}

    for k, v in old_power_levels.items():
        if isinstance(v, collections.abc.Mapping):
            h: Dict[str, int] = {}
            power_levels[k] = h
            for k1, v1 in v.items():
                _copy_power_level_value_as_integer(v1, h, k1)

        else:
            _copy_power_level_value_as_integer(v, power_levels, k)

    return power_levels


def _copy_power_level_value_as_integer(
    old_value: object,
    power_levels: MutableMapping[str, Any],
    key: str,
) -> None:
    """Set `power_levels[key]` to the integer represented by `old_value`.

    :raises TypeError: if `old_value` is not an integer, nor a base-10 string
        representation of an integer.
    """
    if isinstance(old_value, int):
        power_levels[key] = old_value
        return

    if isinstance(old_value, str):
        try:
            parsed_value = int(old_value, base=10)
        except ValueError:
            # Fall through to the final TypeError.
            pass
        else:
            power_levels[key] = parsed_value
            return

    raise TypeError(f"Invalid power_levels value for {key}: {old_value}")


def validate_canonicaljson(value: Any) -> None:
    """
    Ensure that the JSON object is valid according to the rules of canonical JSON.

    See the appendix section 3.1: Canonical JSON.

    This rejects JSON that has:
    * An integer outside the range of [-2 ^ 53 + 1, 2 ^ 53 - 1]
    * Floats
    * NaN, Infinity, -Infinity
    """
    if isinstance(value, int):
        if value < CANONICALJSON_MIN_INT or CANONICALJSON_MAX_INT < value:
            raise SynapseError(400, "JSON integer out of range", Codes.BAD_JSON)

    elif isinstance(value, float):
        # Note that Infinity, -Infinity, and NaN are also considered floats.
        raise SynapseError(400, "Bad JSON value: float", Codes.BAD_JSON)

    elif isinstance(value, collections.abc.Mapping):
        for v in value.values():
            validate_canonicaljson(v)

    elif isinstance(value, (list, tuple)):
        for i in value:
            validate_canonicaljson(i)

    elif not isinstance(value, (bool, str)) and value is not None:
        # Other potential JSON values (bool, None, str) are safe.
        raise SynapseError(400, "Unknown JSON value", Codes.BAD_JSON)
