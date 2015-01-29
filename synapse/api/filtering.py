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
        return self.store.get_user_filter(user_localpart, filter_id)

    def add_user_filter(self, user_localpart, user_filter):
        self._check_valid_filter(user_filter)
        return self.store.add_user_filter(user_localpart, user_filter)

    # TODO(paul): surely we should probably add a delete_user_filter or
    #   replace_user_filter at some point? There's no REST API specified for
    #   them however

    def passes_filter(self, filter_json, event):
        """Check if the event passes through the filter.

        Args:
            filter_json(dict): The filter specification
            event(Event): The event to check
        Returns:
            True if the event passes through the filter.
        """
        return True

    def filter_events(self, events, user, filter_id):
        filter_json = self.get_user_filter(user, filter_id)
        return [e for e in events if self.passes_filter(filter_json, e)]

    def _check_valid_filter(self, user_filter):
        """Check if the provided filter is valid.

        This inspects all definitions contained within the filter.

        Args:
            user_filter(dict): The filter
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
            if key in user_filter:
                self._check_definition(user_filter[key])

        if "room" in user_filter:
            for key in room_level_definitions:
                if key in user_filter["room"]:
                    self._check_definition(user_filter["room"][key])


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

        try:
            event_format = definition["format"]
            if event_format not in ["federation", "events"]:
                raise SynapseError(400, "Invalid format: %s" % (event_format,))
        except KeyError:
            pass  # format is optional

        try:
            event_select_list = definition["select"]
            for select_key in event_select_list:
                if select_key not in ["event_id", "origin_server_ts",
                                      "thread_id", "content", "content.body"]:
                    raise SynapseError(400, "Bad select: %s" % (select_key,))
        except KeyError:
            pass  # select is optional

        if ("bundle_updates" in definition and
                type(definition["bundle_updates"]) != bool):
            raise SynapseError(400, "Bad bundle_updates: expected bool.")
