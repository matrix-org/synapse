# Copyright 2015, 2016 OpenMarket Ltd
# Copyright 2017 Vector Creations Ltd
# Copyright 2018-2019 New Vector Ltd
# Copyright 2019-2021 The Matrix.org Foundation C.I.C.
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
import json
from typing import (
    TYPE_CHECKING,
    Awaitable,
    Callable,
    Collection,
    Dict,
    Iterable,
    List,
    Mapping,
    Optional,
    Set,
    TypeVar,
    Union,
)

import jsonschema
from jsonschema import FormatChecker

from synapse.api.constants import EduTypes, EventContentFields
from synapse.api.errors import SynapseError
from synapse.api.presence import UserPresenceState
from synapse.events import EventBase
from synapse.types import JsonDict, RoomID, UserID

if TYPE_CHECKING:
    from synapse.server import HomeServer

FILTER_SCHEMA = {
    "additionalProperties": False,
    "type": "object",
    "properties": {
        "limit": {"type": "number"},
        "senders": {"$ref": "#/definitions/user_id_array"},
        "not_senders": {"$ref": "#/definitions/user_id_array"},
        # TODO: We don't limit event type values but we probably should...
        # check types are valid event types
        "types": {"type": "array", "items": {"type": "string"}},
        "not_types": {"type": "array", "items": {"type": "string"}},
    },
}

ROOM_FILTER_SCHEMA = {
    "additionalProperties": False,
    "type": "object",
    "properties": {
        "not_rooms": {"$ref": "#/definitions/room_id_array"},
        "rooms": {"$ref": "#/definitions/room_id_array"},
        "ephemeral": {"$ref": "#/definitions/room_event_filter"},
        "include_leave": {"type": "boolean"},
        "state": {"$ref": "#/definitions/room_event_filter"},
        "timeline": {"$ref": "#/definitions/room_event_filter"},
        "account_data": {"$ref": "#/definitions/room_event_filter"},
    },
}

ROOM_EVENT_FILTER_SCHEMA = {
    "additionalProperties": False,
    "type": "object",
    "properties": {
        "limit": {"type": "number"},
        "senders": {"$ref": "#/definitions/user_id_array"},
        "not_senders": {"$ref": "#/definitions/user_id_array"},
        "types": {"type": "array", "items": {"type": "string"}},
        "not_types": {"type": "array", "items": {"type": "string"}},
        "rooms": {"$ref": "#/definitions/room_id_array"},
        "not_rooms": {"$ref": "#/definitions/room_id_array"},
        "contains_url": {"type": "boolean"},
        "lazy_load_members": {"type": "boolean"},
        "include_redundant_members": {"type": "boolean"},
        # Include or exclude events with the provided labels.
        # cf https://github.com/matrix-org/matrix-doc/pull/2326
        "org.matrix.labels": {"type": "array", "items": {"type": "string"}},
        "org.matrix.not_labels": {"type": "array", "items": {"type": "string"}},
        # MSC3440, filtering by event relations.
        "related_by_senders": {"type": "array", "items": {"type": "string"}},
        "related_by_rel_types": {"type": "array", "items": {"type": "string"}},
    },
}

USER_ID_ARRAY_SCHEMA = {
    "type": "array",
    "items": {"type": "string", "format": "matrix_user_id"},
}

ROOM_ID_ARRAY_SCHEMA = {
    "type": "array",
    "items": {"type": "string", "format": "matrix_room_id"},
}

USER_FILTER_SCHEMA = {
    "$schema": "http://json-schema.org/draft-04/schema#",
    "description": "schema for a Sync filter",
    "type": "object",
    "definitions": {
        "room_id_array": ROOM_ID_ARRAY_SCHEMA,
        "user_id_array": USER_ID_ARRAY_SCHEMA,
        "filter": FILTER_SCHEMA,
        "room_filter": ROOM_FILTER_SCHEMA,
        "room_event_filter": ROOM_EVENT_FILTER_SCHEMA,
    },
    "properties": {
        "presence": {"$ref": "#/definitions/filter"},
        "account_data": {"$ref": "#/definitions/filter"},
        "room": {"$ref": "#/definitions/room_filter"},
        "event_format": {"type": "string", "enum": ["client", "federation"]},
        "event_fields": {
            "type": "array",
            "items": {
                "type": "string",
                # Don't allow '\\' in event field filters. This makes matching
                # events a lot easier as we can then use a negative lookbehind
                # assertion to split '\.' If we allowed \\ then it would
                # incorrectly split '\\.' See synapse.events.utils.serialize_event
                #
                # Note that because this is a regular expression, we have to escape
                # each backslash in the pattern.
                "pattern": r"^((?!\\\\).)*$",
            },
        },
    },
    "additionalProperties": False,
}


@FormatChecker.cls_checks("matrix_room_id")
def matrix_room_id_validator(room_id: object) -> bool:
    return isinstance(room_id, str) and RoomID.is_valid(room_id)


@FormatChecker.cls_checks("matrix_user_id")
def matrix_user_id_validator(user_id: object) -> bool:
    return isinstance(user_id, str) and UserID.is_valid(user_id)


class Filtering:
    def __init__(self, hs: "HomeServer"):
        self._hs = hs
        self.store = hs.get_datastores().main

        self.DEFAULT_FILTER_COLLECTION = FilterCollection(hs, {})

    async def get_user_filter(
        self, user_localpart: str, filter_id: Union[int, str]
    ) -> "FilterCollection":
        result = await self.store.get_user_filter(user_localpart, filter_id)
        return FilterCollection(self._hs, result)

    def add_user_filter(
        self, user_localpart: str, user_filter: JsonDict
    ) -> Awaitable[int]:
        self.check_valid_filter(user_filter)
        return self.store.add_user_filter(user_localpart, user_filter)

    # TODO(paul): surely we should probably add a delete_user_filter or
    #   replace_user_filter at some point? There's no REST API specified for
    #   them however

    def check_valid_filter(self, user_filter_json: JsonDict) -> None:
        """Check if the provided filter is valid.

        This inspects all definitions contained within the filter.

        Args:
            user_filter_json: The filter
        Raises:
            SynapseError: If the filter is not valid.
        """
        # NB: Filters are the complete json blobs. "Definitions" are an
        # individual top-level key e.g. public_user_data. Filters are made of
        # many definitions.
        try:
            jsonschema.validate(
                user_filter_json, USER_FILTER_SCHEMA, format_checker=FormatChecker()
            )
        except jsonschema.ValidationError as e:
            raise SynapseError(400, str(e))


# Filters work across events, presence EDUs, and account data.
FilterEvent = TypeVar("FilterEvent", EventBase, UserPresenceState, JsonDict)


class FilterCollection:
    def __init__(self, hs: "HomeServer", filter_json: JsonDict):
        self._filter_json = filter_json

        room_filter_json = self._filter_json.get("room", {})

        self._room_filter = Filter(
            hs,
            {k: v for k, v in room_filter_json.items() if k in ("rooms", "not_rooms")},
        )

        self._room_timeline_filter = Filter(hs, room_filter_json.get("timeline", {}))
        self._room_state_filter = Filter(hs, room_filter_json.get("state", {}))
        self._room_ephemeral_filter = Filter(hs, room_filter_json.get("ephemeral", {}))
        self._room_account_data = Filter(hs, room_filter_json.get("account_data", {}))
        self._presence_filter = Filter(hs, filter_json.get("presence", {}))
        self._account_data = Filter(hs, filter_json.get("account_data", {}))

        self.include_leave = filter_json.get("room", {}).get("include_leave", False)
        self.event_fields = filter_json.get("event_fields", [])
        self.event_format = filter_json.get("event_format", "client")

    def __repr__(self) -> str:
        return "<FilterCollection %s>" % (json.dumps(self._filter_json),)

    def get_filter_json(self) -> JsonDict:
        return self._filter_json

    def timeline_limit(self) -> int:
        return self._room_timeline_filter.limit

    def presence_limit(self) -> int:
        return self._presence_filter.limit

    def ephemeral_limit(self) -> int:
        return self._room_ephemeral_filter.limit

    def lazy_load_members(self) -> bool:
        return self._room_state_filter.lazy_load_members

    def include_redundant_members(self) -> bool:
        return self._room_state_filter.include_redundant_members

    async def filter_presence(
        self, events: Iterable[UserPresenceState]
    ) -> List[UserPresenceState]:
        return await self._presence_filter.filter(events)

    async def filter_account_data(self, events: Iterable[JsonDict]) -> List[JsonDict]:
        return await self._account_data.filter(events)

    async def filter_room_state(self, events: Iterable[EventBase]) -> List[EventBase]:
        return await self._room_state_filter.filter(
            await self._room_filter.filter(events)
        )

    async def filter_room_timeline(
        self, events: Iterable[EventBase]
    ) -> List[EventBase]:
        return await self._room_timeline_filter.filter(
            await self._room_filter.filter(events)
        )

    async def filter_room_ephemeral(self, events: Iterable[JsonDict]) -> List[JsonDict]:
        return await self._room_ephemeral_filter.filter(
            await self._room_filter.filter(events)
        )

    async def filter_room_account_data(
        self, events: Iterable[JsonDict]
    ) -> List[JsonDict]:
        return await self._room_account_data.filter(
            await self._room_filter.filter(events)
        )

    def blocks_all_presence(self) -> bool:
        return (
            self._presence_filter.filters_all_types()
            or self._presence_filter.filters_all_senders()
        )

    def blocks_all_room_ephemeral(self) -> bool:
        return (
            self._room_ephemeral_filter.filters_all_types()
            or self._room_ephemeral_filter.filters_all_senders()
            or self._room_ephemeral_filter.filters_all_rooms()
        )

    def blocks_all_room_timeline(self) -> bool:
        return (
            self._room_timeline_filter.filters_all_types()
            or self._room_timeline_filter.filters_all_senders()
            or self._room_timeline_filter.filters_all_rooms()
        )


class Filter:
    def __init__(self, hs: "HomeServer", filter_json: JsonDict):
        self._hs = hs
        self._store = hs.get_datastores().main
        self.filter_json = filter_json

        self.limit = filter_json.get("limit", 10)
        self.lazy_load_members = filter_json.get("lazy_load_members", False)
        self.include_redundant_members = filter_json.get(
            "include_redundant_members", False
        )

        self.types = filter_json.get("types", None)
        self.not_types = filter_json.get("not_types", [])

        self.rooms = filter_json.get("rooms", None)
        self.not_rooms = filter_json.get("not_rooms", [])

        self.senders = filter_json.get("senders", None)
        self.not_senders = filter_json.get("not_senders", [])

        self.contains_url = filter_json.get("contains_url", None)

        self.labels = filter_json.get("org.matrix.labels", None)
        self.not_labels = filter_json.get("org.matrix.not_labels", [])

        self.related_by_senders = self.filter_json.get("related_by_senders", None)
        self.related_by_rel_types = self.filter_json.get("related_by_rel_types", None)

    def filters_all_types(self) -> bool:
        return "*" in self.not_types

    def filters_all_senders(self) -> bool:
        return "*" in self.not_senders

    def filters_all_rooms(self) -> bool:
        return "*" in self.not_rooms

    def _check(self, event: FilterEvent) -> bool:
        """Checks whether the filter matches the given event.

        Args:
            event: The event, account data, or presence to check against this
                filter.

        Returns:
            True if the event matches the filter.
        """
        # We usually get the full "events" as dictionaries coming through,
        # except for presence which actually gets passed around as its own type.
        if isinstance(event, UserPresenceState):
            user_id = event.user_id
            field_matchers = {
                "senders": lambda v: user_id == v,
                "types": lambda v: EduTypes.PRESENCE == v,
            }
            return self._check_fields(field_matchers)
        else:
            content = event.get("content")
            # Content is assumed to be a mapping below, so ensure it is. This should
            # always be true for events, but account_data has been allowed to
            # have non-dict content.
            if not isinstance(content, Mapping):
                content = {}

            sender = event.get("sender", None)
            if not sender:
                # Presence events had their 'sender' in content.user_id, but are
                # now handled above. We don't know if anything else uses this
                # form. TODO: Check this and probably remove it.
                sender = content.get("user_id")

            room_id = event.get("room_id", None)
            ev_type = event.get("type", None)

            # check if there is a string url field in the content for filtering purposes
            labels = content.get(EventContentFields.LABELS, [])

            field_matchers = {
                "rooms": lambda v: room_id == v,
                "senders": lambda v: sender == v,
                "types": lambda v: _matches_wildcard(ev_type, v),
                "labels": lambda v: v in labels,
            }

            result = self._check_fields(field_matchers)
            if not result:
                return result

            contains_url_filter = self.contains_url
            if contains_url_filter is not None:
                contains_url = isinstance(content.get("url"), str)
                if contains_url_filter != contains_url:
                    return False

            return True

    def _check_fields(self, field_matchers: Dict[str, Callable[[str], bool]]) -> bool:
        """Checks whether the filter matches the given event fields.

        Args:
            field_matchers: A map of attribute name to callable to use for checking
                particular fields.

                The attribute name and an inverse (not_<attribute name>) must
                exist on the Filter.

                The callable should return true if the event's value matches the
                filter's value.

        Returns:
            True if the event fields match
        """

        for name, match_func in field_matchers.items():
            # If the event matches one of the disallowed values, reject it.
            not_name = "not_%s" % (name,)
            disallowed_values = getattr(self, not_name)
            if any(map(match_func, disallowed_values)):
                return False

            # Other the event does not match at least one of the allowed values,
            # reject it.
            allowed_values = getattr(self, name)
            if allowed_values is not None:
                if not any(map(match_func, allowed_values)):
                    return False

        # Otherwise, accept it.
        return True

    def filter_rooms(self, room_ids: Iterable[str]) -> Set[str]:
        """Apply the 'rooms' filter to a given list of rooms.

        Args:
            room_ids: A list of room_ids.

        Returns:
            A list of room_ids that match the filter
        """
        room_ids = set(room_ids)

        disallowed_rooms = set(self.not_rooms)
        room_ids -= disallowed_rooms

        allowed_rooms = self.rooms
        if allowed_rooms is not None:
            room_ids &= set(allowed_rooms)

        return room_ids

    async def _check_event_relations(
        self, events: Collection[FilterEvent]
    ) -> List[FilterEvent]:
        # The event IDs to check, mypy doesn't understand the isinstance check.
        event_ids = [event.event_id for event in events if isinstance(event, EventBase)]  # type: ignore[attr-defined]
        event_ids_to_keep = set(
            await self._store.events_have_relations(
                event_ids, self.related_by_senders, self.related_by_rel_types
            )
        )

        return [
            event
            for event in events
            if not isinstance(event, EventBase) or event.event_id in event_ids_to_keep
        ]

    async def filter(self, events: Iterable[FilterEvent]) -> List[FilterEvent]:
        result = [event for event in events if self._check(event)]

        if self.related_by_senders or self.related_by_rel_types:
            return await self._check_event_relations(result)

        return result

    def with_room_ids(self, room_ids: Iterable[str]) -> "Filter":
        """Returns a new filter with the given room IDs appended.

        Args:
            room_ids: The room_ids to add

        Returns:
            filter: A new filter including the given rooms and the old
                    filter's rooms.
        """
        newFilter = Filter(self._hs, self.filter_json)
        newFilter.rooms += room_ids
        return newFilter


def _matches_wildcard(actual_value: Optional[str], filter_value: str) -> bool:
    if filter_value.endswith("*") and isinstance(actual_value, str):
        type_prefix = filter_value[:-1]
        return actual_value.startswith(type_prefix)
    else:
        return actual_value == filter_value
