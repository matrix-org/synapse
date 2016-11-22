# -*- coding: utf-8 -*-
# Copyright 2015, 2016 OpenMarket Ltd
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
from synapse.api.errors import SynapseError
from synapse.types import UserID, RoomID

from twisted.internet import defer

import ujson as json


class Filtering(object):

    def __init__(self, hs):
        super(Filtering, self).__init__()
        self.store = hs.get_datastore()

    @defer.inlineCallbacks
    def get_user_filter(self, user_localpart, filter_id):
        result = yield self.store.get_user_filter(user_localpart, filter_id)
        defer.returnValue(FilterCollection(result))

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

        top_level_definitions = [
            "presence", "account_data"
        ]

        room_level_definitions = [
            "state", "timeline", "ephemeral", "account_data"
        ]

        for key in top_level_definitions:
            if key in user_filter_json:
                self._check_definition(user_filter_json[key])

        if "room" in user_filter_json:
            self._check_definition_room_lists(user_filter_json["room"])
            for key in room_level_definitions:
                if key in user_filter_json["room"]:
                    self._check_definition(user_filter_json["room"][key])

        if "event_fields" in user_filter_json:
            if type(user_filter_json["event_fields"]) != list:
                raise SynapseError(400, "event_fields must be a list of strings")
            for field in user_filter_json["event_fields"]:
                if not isinstance(field, basestring):
                    raise SynapseError(400, "Event field must be a string")
                # Don't allow '\\' in event field filters. This makes matching
                # events a lot easier as we can then use a negative lookbehind
                # assertion to split '\.' If we allowed \\ then it would
                # incorrectly split '\\.' See synapse.events.utils.serialize_event
                if r'\\' in field:
                    raise SynapseError(
                        400, r'The escape character \ cannot itself be escaped'
                    )

    def _check_definition_room_lists(self, definition):
        """Check that "rooms" and "not_rooms" are lists of room ids if they
        are present

        Args:
            definition(dict): The filter definition
        Raises:
            SynapseError: If there was a problem with this definition.
        """
        # check rooms are valid room IDs
        room_id_keys = ["rooms", "not_rooms"]
        for key in room_id_keys:
            if key in definition:
                if type(definition[key]) != list:
                    raise SynapseError(400, "Expected %s to be a list." % key)
                for room_id in definition[key]:
                    RoomID.from_string(room_id)

    def _check_definition(self, definition):
        """Check if the provided definition is valid.

        This inspects not only the types but also the values to make sure they
        make sense.

        Args:
            definition(dict): The filter definition
        Raises:
            SynapseError: If there was a problem with this definition.
        """
        # NB: Filters are the complete json blobs. "Definitions" are an
        # individual top-level key e.g. public_user_data. Filters are made of
        # many definitions.
        if type(definition) != dict:
            raise SynapseError(
                400, "Expected JSON object, not %s" % (definition,)
            )

        self._check_definition_room_lists(definition)

        # check senders are valid user IDs
        user_id_keys = ["senders", "not_senders"]
        for key in user_id_keys:
            if key in definition:
                if type(definition[key]) != list:
                    raise SynapseError(400, "Expected %s to be a list." % key)
                for user_id in definition[key]:
                    UserID.from_string(user_id)

        # TODO: We don't limit event type values but we probably should...
        # check types are valid event types
        event_keys = ["types", "not_types"]
        for key in event_keys:
            if key in definition:
                if type(definition[key]) != list:
                    raise SynapseError(400, "Expected %s to be a list." % key)
                for event_type in definition[key]:
                    if not isinstance(event_type, basestring):
                        raise SynapseError(400, "Event type should be a string")


class FilterCollection(object):
    def __init__(self, filter_json):
        self._filter_json = filter_json

        room_filter_json = self._filter_json.get("room", {})

        self._room_filter = Filter({
            k: v for k, v in room_filter_json.items()
            if k in ("rooms", "not_rooms")
        })

        self._room_timeline_filter = Filter(room_filter_json.get("timeline", {}))
        self._room_state_filter = Filter(room_filter_json.get("state", {}))
        self._room_ephemeral_filter = Filter(room_filter_json.get("ephemeral", {}))
        self._room_account_data = Filter(room_filter_json.get("account_data", {}))
        self._presence_filter = Filter(filter_json.get("presence", {}))
        self._account_data = Filter(filter_json.get("account_data", {}))

        self.include_leave = filter_json.get("room", {}).get(
            "include_leave", False
        )
        self.event_fields = filter_json.get("event_fields", [])

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
            self._presence_filter.filters_all_types() or
            self._presence_filter.filters_all_senders()
        )

    def blocks_all_room_ephemeral(self):
        return (
            self._room_ephemeral_filter.filters_all_types() or
            self._room_ephemeral_filter.filters_all_senders() or
            self._room_ephemeral_filter.filters_all_rooms()
        )

    def blocks_all_room_timeline(self):
        return (
            self._room_timeline_filter.filters_all_types() or
            self._room_timeline_filter.filters_all_senders() or
            self._room_timeline_filter.filters_all_rooms()
        )


class Filter(object):
    def __init__(self, filter_json):
        self.filter_json = filter_json

        self.types = self.filter_json.get("types", None)
        self.not_types = self.filter_json.get("not_types", [])

        self.rooms = self.filter_json.get("rooms", None)
        self.not_rooms = self.filter_json.get("not_rooms", [])

        self.senders = self.filter_json.get("senders", None)
        self.not_senders = self.filter_json.get("not_senders", [])

        self.contains_url = self.filter_json.get("contains_url", None)

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
        sender = event.get("sender", None)
        if not sender:
            # Presence events have their 'sender' in content.user_id
            content = event.get("content")
            # account_data has been allowed to have non-dict content, so check type first
            if isinstance(content, dict):
                sender = content.get("user_id")

        return self.check_fields(
            event.get("room_id", None),
            sender,
            event.get("type", None),
            "url" in event.get("content", {})
        )

    def check_fields(self, room_id, sender, event_type, contains_url):
        """Checks whether the filter matches the given event fields.

        Returns:
            bool: True if the event fields match
        """
        literal_keys = {
            "rooms": lambda v: room_id == v,
            "senders": lambda v: sender == v,
            "types": lambda v: _matches_wildcard(event_type, v)
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
        return filter(self.check, events)

    def limit(self):
        return self.filter_json.get("limit", 10)


def _matches_wildcard(actual_value, filter_value):
    if filter_value.endswith("*"):
        type_prefix = filter_value[:-1]
        return actual_value.startswith(type_prefix)
    else:
        return actual_value == filter_value


DEFAULT_FILTER_COLLECTION = FilterCollection({})
