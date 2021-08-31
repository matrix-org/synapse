# Copyright 2015, 2016 OpenMarket Ltd
# Copyright 2017 Vector Creations Ltd
# Copyright 2018-2019 New Vector Ltd
# Copyright 2019 The Matrix.org Foundation C.I.C.
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
from typing import List

import jsonschema
from jsonschema import FormatChecker

from synapse.api.constants import EventContentFields
from synapse.api.errors import SynapseError
from synapse.api.presence import UserPresenceState
from synapse.types import RoomID, UserID

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
def matrix_room_id_validator(room_id_str):
    return RoomID.from_string(room_id_str)


@FormatChecker.cls_checks("matrix_user_id")
def matrix_user_id_validator(user_id_str):
    return UserID.from_string(user_id_str)


class Filtering:
    def __init__(self, hs):
        super().__init__()
        self.store = hs.get_datastore()

    async def get_user_filter(self, user_localpart, filter_id):
        result = await self.store.get_user_filter(user_localpart, filter_id)
        return FilterCollection(result)

    def add_user_filter(self, user_localpart, user_filter):
        self.check_valid_filter(user_filter)
        return self.store.add_user_filter(user_localpart, user_filter)

    # TODO(paul): surely we should probably add a delete_user_filter or
    #   replace_user_filter at some point? There's no REST API specified for
    #   them however

    def check_valid_filter(self, user_filter_json):
        """Check if the provided filter is valid.

        This inspects all definitions contained within the filter.

        Args:
            user_filter_json(dict): The filter
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


class FilterCollection:
    def __init__(self, filter_json):
        self._filter_json = filter_json

        room_filter_json = self._filter_json.get("room", {})

        self._room_filter = Filter(
            {k: v for k, v in room_filter_json.items() if k in ("rooms", "not_rooms")}
        )

        self._room_timeline_filter = Filter(room_filter_json.get("timeline", {}))
        self._room_state_filter = Filter(room_filter_json.get("state", {}))
        self._room_ephemeral_filter = Filter(room_filter_json.get("ephemeral", {}))
        self._room_account_data = Filter(room_filter_json.get("account_data", {}))
        self._presence_filter = Filter(filter_json.get("presence", {}))
        self._account_data = Filter(filter_json.get("account_data", {}))

        self.include_leave = filter_json.get("room", {}).get("include_leave", False)
        self.event_fields = filter_json.get("event_fields", [])
        self.event_format = filter_json.get("event_format", "client")

    def __repr__(self):
        return "<FilterCollection %s>" % (json.dumps(self._filter_json),)

    def get_filter_json(self):
        return self._filter_json

    def timeline_limit(self):
        return self._room_timeline_filter.limit()

    def presence_limit(self):
        return self._presence_filter.limit()

    def ephemeral_limit(self):
        return self._room_ephemeral_filter.limit()

    def lazy_load_members(self):
        return self._room_state_filter.lazy_load_members()

    def include_redundant_members(self):
        return self._room_state_filter.include_redundant_members()

    def filter_presence(self, events):
        return self._presence_filter.filter(events)

    def filter_account_data(self, events):
        return self._account_data.filter(events)

    def filter_room_state(self, events):
        return self._room_state_filter.filter(self._room_filter.filter(events))

    def filter_room_timeline(self, events):
        return self._room_timeline_filter.filter(self._room_filter.filter(events))

    def filter_room_ephemeral(self, events):
        return self._room_ephemeral_filter.filter(self._room_filter.filter(events))

    def filter_room_account_data(self, events):
        return self._room_account_data.filter(self._room_filter.filter(events))

    def blocks_all_presence(self):
        return (
            self._presence_filter.filters_all_types()
            or self._presence_filter.filters_all_senders()
        )

    def blocks_all_room_ephemeral(self):
        return (
            self._room_ephemeral_filter.filters_all_types()
            or self._room_ephemeral_filter.filters_all_senders()
            or self._room_ephemeral_filter.filters_all_rooms()
        )

    def blocks_all_room_timeline(self):
        return (
            self._room_timeline_filter.filters_all_types()
            or self._room_timeline_filter.filters_all_senders()
            or self._room_timeline_filter.filters_all_rooms()
        )


class Filter:
    def __init__(self, filter_json):
        self.filter_json = filter_json

        self.types = self.filter_json.get("types", None)
        self.not_types = self.filter_json.get("not_types", [])

        self.rooms = self.filter_json.get("rooms", None)
        self.not_rooms = self.filter_json.get("not_rooms", [])

        self.senders = self.filter_json.get("senders", None)
        self.not_senders = self.filter_json.get("not_senders", [])

        self.contains_url = self.filter_json.get("contains_url", None)

        self.labels = self.filter_json.get("org.matrix.labels", None)
        self.not_labels = self.filter_json.get("org.matrix.not_labels", [])

    def filters_all_types(self):
        return "*" in self.not_types

    def filters_all_senders(self):
        return "*" in self.not_senders

    def filters_all_rooms(self):
        return "*" in self.not_rooms

    def check(self, event):
        """Checks whether the filter matches the given event.

        Returns:
            bool: True if the event matches
        """
        # We usually get the full "events" as dictionaries coming through,
        # except for presence which actually gets passed around as its own
        # namedtuple type.
        if isinstance(event, UserPresenceState):
            sender = event.user_id
            room_id = None
            ev_type = "m.presence"
            contains_url = False
            labels = []  # type: List[str]
        else:
            sender = event.get("sender", None)
            if not sender:
                # Presence events had their 'sender' in content.user_id, but are
                # now handled above. We don't know if anything else uses this
                # form. TODO: Check this and probably remove it.
                content = event.get("content")
                # account_data has been allowed to have non-dict content, so
                # check type first
                if isinstance(content, dict):
                    sender = content.get("user_id")

            room_id = event.get("room_id", None)
            ev_type = event.get("type", None)

            content = event.get("content", {})
            # check if there is a string url field in the content for filtering purposes
            contains_url = isinstance(content.get("url"), str)
            labels = content.get(EventContentFields.LABELS, [])

        return self.check_fields(room_id, sender, ev_type, labels, contains_url)

    def check_fields(self, room_id, sender, event_type, labels, contains_url):
        """Checks whether the filter matches the given event fields.

        Returns:
            bool: True if the event fields match
        """
        literal_keys = {
            "rooms": lambda v: room_id == v,
            "senders": lambda v: sender == v,
            "types": lambda v: _matches_wildcard(event_type, v),
            "labels": lambda v: v in labels,
        }

        for name, match_func in literal_keys.items():
            not_name = "not_%s" % (name,)
            disallowed_values = getattr(self, not_name)
            if any(map(match_func, disallowed_values)):
                return False

            allowed_values = getattr(self, name)
            if allowed_values is not None:
                if not any(map(match_func, allowed_values)):
                    return False

        contains_url_filter = self.filter_json.get("contains_url")
        if contains_url_filter is not None:
            if contains_url_filter != contains_url:
                return False

        return True

    def filter_rooms(self, room_ids):
        """Apply the 'rooms' filter to a given list of rooms.

        Args:
            room_ids (list): A list of room_ids.

        Returns:
            list: A list of room_ids that match the filter
        """
        room_ids = set(room_ids)

        disallowed_rooms = set(self.filter_json.get("not_rooms", []))
        room_ids -= disallowed_rooms

        allowed_rooms = self.filter_json.get("rooms", None)
        if allowed_rooms is not None:
            room_ids &= set(allowed_rooms)

        return room_ids

    def filter(self, events):
        return list(filter(self.check, events))

    def limit(self):
        return self.filter_json.get("limit", 10)

    def lazy_load_members(self):
        return self.filter_json.get("lazy_load_members", False)

    def include_redundant_members(self):
        return self.filter_json.get("include_redundant_members", False)

    def with_room_ids(self, room_ids):
        """Returns a new filter with the given room IDs appended.

        Args:
            room_ids (iterable[unicode]): The room_ids to add

        Returns:
            filter: A new filter including the given rooms and the old
                    filter's rooms.
        """
        newFilter = Filter(self.filter_json)
        newFilter.rooms += room_ids
        return newFilter


def _matches_wildcard(actual_value, filter_value):
    if filter_value.endswith("*"):
        type_prefix = filter_value[:-1]
        return actual_value.startswith(type_prefix)
    else:
        return actual_value == filter_value


DEFAULT_FILTER_COLLECTION = FilterCollection({})
