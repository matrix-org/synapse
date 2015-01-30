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
        result.addCallback(Filter)
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
            "public_user_data", "private_user_data", "server_data"
        ]

        room_level_definitions = [
            "state", "events", "ephemeral"
        ]

        for key in top_level_definitions:
            if key in user_filter_json:
                self._check_definition(user_filter_json[key])

        if "room" in user_filter_json:
            for key in room_level_definitions:
                if key in user_filter_json["room"]:
                    self._check_definition(user_filter_json["room"][key])

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

        # check rooms are valid room IDs
        room_id_keys = ["rooms", "not_rooms"]
        for key in room_id_keys:
            if key in definition:
                if type(definition[key]) != list:
                    raise SynapseError(400, "Expected %s to be a list." % key)
                for room_id in definition[key]:
                    RoomID.from_string(room_id)

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

        if "format" in definition:
            event_format = definition["format"]
            if event_format not in ["federation", "events"]:
                raise SynapseError(400, "Invalid format: %s" % (event_format,))

        if "select" in definition:
            event_select_list = definition["select"]
            for select_key in event_select_list:
                if select_key not in ["event_id", "origin_server_ts",
                                      "thread_id", "content", "content.body"]:
                    raise SynapseError(400, "Bad select: %s" % (select_key,))

        if ("bundle_updates" in definition and
                type(definition["bundle_updates"]) != bool):
            raise SynapseError(400, "Bad bundle_updates: expected bool.")


class Filter(object):
    def __init__(self, filter_json):
        self.filter_json = filter_json

    def filter_public_user_data(self, events):
        return self._filter_on_key(events, ["public_user_data"])

    def filter_private_user_data(self, events):
        return self._filter_on_key(events, ["private_user_data"])

    def filter_room_state(self, events):
        return self._filter_on_key(events, ["room", "state"])

    def filter_room_events(self, events):
        return self._filter_on_key(events, ["room", "events"])

    def filter_room_ephemeral(self, events):
        return self._filter_on_key(events, ["room", "ephemeral"])

    def _filter_on_key(self, events, keys):
        filter_json = self.filter_json
        if not filter_json:
            return events

        try:
            # extract the right definition from the filter
            definition = filter_json
            for key in keys:
                definition = definition[key]
            return self._filter_with_definition(events, definition)
        except KeyError:
            # return all events if definition isn't specified.
            return events

    def _filter_with_definition(self, events, definition):
        return [e for e in events if self._passes_definition(definition, e)]

    def _passes_definition(self, definition, event):
        """Check if the event passes through the given definition.

        Args:
            definition(dict): The definition to check against.
            event(Event): The event to check.
        Returns:
            True if the event passes through the filter.
        """
        # Algorithm notes:
        # For each key in the definition, check the event meets the criteria:
        #   * For types: Literal match or prefix match (if ends with wildcard)
        #   * For senders/rooms: Literal match only
        #   * "not_" checks take presedence (e.g. if "m.*" is in both 'types'
        #     and 'not_types' then it is treated as only being in 'not_types')

        # room checks
        if hasattr(event, "room_id"):
            room_id = event.room_id
            allow_rooms = definition.get("rooms", None)
            reject_rooms = definition.get("not_rooms", None)
            if reject_rooms and room_id in reject_rooms:
                return False
            if allow_rooms and room_id not in allow_rooms:
                return False

        # sender checks
        if hasattr(event, "sender"):
            # Should we be including event.state_key for some event types?
            sender = event.sender
            allow_senders = definition.get("senders", None)
            reject_senders = definition.get("not_senders", None)
            if reject_senders and sender in reject_senders:
                return False
            if allow_senders and sender not in allow_senders:
                return False

        # type checks
        if "not_types" in definition:
            for def_type in definition["not_types"]:
                if self._event_matches_type(event, def_type):
                    return False
        if "types" in definition:
            included = False
            for def_type in definition["types"]:
                if self._event_matches_type(event, def_type):
                    included = True
                    break
            if not included:
                return False

        return True

    def _event_matches_type(self, event, def_type):
        if def_type.endswith("*"):
            type_prefix = def_type[:-1]
            return event.type.startswith(type_prefix)
        else:
            return event.type == def_type
