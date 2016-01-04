# -*- coding: utf-8 -*-
# Copyright 2015 OpenMarket Ltd
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


class Filtering(object):

    def __init__(self, hs):
        super(Filtering, self).__init__()
        self.store = hs.get_datastore()

    def get_user_filter(self, user_localpart, filter_id):
        result = self.store.get_user_filter(user_localpart, filter_id)
        result.addCallback(FilterCollection)
        return result

    def add_user_filter(self, user_localpart, user_filter):
        self._check_valid_filter(user_filter)
        return self.store.add_user_filter(user_localpart, user_filter)

    # TODO(paul): surely we should probably add a delete_user_filter or
    #   replace_user_filter at some point? There's no REST API specified for
    #   them however

    def _check_valid_filter(self, user_filter_json):
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
        self.filter_json = filter_json

        room_filter_json = self.filter_json.get("room", {})

        self.room_filter = Filter({
            k: v for k, v in room_filter_json.items()
            if k in ("rooms", "not_rooms")
        })

        self.room_timeline_filter = Filter(room_filter_json.get("timeline", {}))
        self.room_state_filter = Filter(room_filter_json.get("state", {}))
        self.room_ephemeral_filter = Filter(room_filter_json.get("ephemeral", {}))
        self.room_account_data = Filter(room_filter_json.get("account_data", {}))
        self.presence_filter = Filter(self.filter_json.get("presence", {}))
        self.account_data = Filter(self.filter_json.get("account_data", {}))

        self.include_leave = self.filter_json.get("room", {}).get(
            "include_leave", False
        )

    def list_rooms(self):
        return self.room_filter.list_rooms()

    def timeline_limit(self):
        return self.room_timeline_filter.limit()

    def presence_limit(self):
        return self.presence_filter.limit()

    def ephemeral_limit(self):
        return self.room_ephemeral_filter.limit()

    def filter_presence(self, events):
        return self.presence_filter.filter(events)

    def filter_account_data(self, events):
        return self.account_data.filter(events)

    def filter_room_state(self, events):
        return self.room_state_filter.filter(self.room_filter.filter(events))

    def filter_room_timeline(self, events):
        return self.room_timeline_filter.filter(self.room_filter.filter(events))

    def filter_room_ephemeral(self, events):
        return self.room_ephemeral_filter.filter(self.room_filter.filter(events))

    def filter_room_account_data(self, events):
        return self.room_account_data.filter(self.room_filter.filter(events))


class Filter(object):
    def __init__(self, filter_json):
        self.filter_json = filter_json

    def list_rooms(self):
        """The list of room_id strings this filter restricts the output to
        or None if the this filter doesn't list the room ids.
        """
        if "rooms" in self.filter_json:
            return list(set(self.filter_json["rooms"]))
        else:
            return None

    def check(self, event):
        """Checks whether the filter matches the given event.

        Returns:
            bool: True if the event matches
        """
        if isinstance(event, dict):
            return self.check_fields(
                event.get("room_id", None),
                event.get("sender", None),
                event.get("type", None),
            )
        else:
            return self.check_fields(
                getattr(event, "room_id", None),
                getattr(event, "sender", None),
                event.type,
            )

    def check_fields(self, room_id, sender, event_type):
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
            disallowed_values = self.filter_json.get(not_name, [])
            if any(map(match_func, disallowed_values)):
                return False

            allowed_values = self.filter_json.get(name, None)
            if allowed_values is not None:
                if not any(map(match_func, allowed_values)):
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
