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
from synapse.api.constants import EventTypes

import re


class ApplicationService(object):
    """Defines an application service. This definition is mostly what is
    provided to the /register AS API.

    Provides methods to check if this service is "interested" in events.
    """
    NS_USERS = "users"
    NS_ALIASES = "aliases"
    NS_ROOMS = "rooms"
    # The ordering here is important as it is used to map database values (which
    # are stored as ints representing the position in this list) to namespace
    # values.
    NS_LIST = [NS_USERS, NS_ALIASES, NS_ROOMS]

    def __init__(self, token, url=None, namespaces=None):
        self.token = token
        self.url = url
        self.namespaces = self._check_namespaces(namespaces)

    def _check_namespaces(self, namespaces):
        # Sanity check that it is of the form:
        # {
        #   users: ["regex",...],
        #   aliases: ["regex",...],
        #   rooms: ["regex",...],
        # }
        if not namespaces:
            return None

        for ns in ApplicationService.NS_LIST:
            if type(namespaces[ns]) != list:
                raise ValueError("Bad namespace value for '%s'", ns)
            for regex in namespaces[ns]:
                if not isinstance(regex, basestring):
                    raise ValueError("Expected string regex for ns '%s'", ns)
        return namespaces

    def _matches_regex(self, test_string, namespace_key):
        for regex in self.namespaces[namespace_key]:
            if re.match(regex, test_string):
                return True
        return False

    def _matches_user(self, event):
        if (hasattr(event, "user_id") and
                self._matches_regex(
                event.user_id, ApplicationService.NS_USERS)):
            return True
        # also check m.room.member state key
        if (hasattr(event, "type") and event.type == EventTypes.Member
                and hasattr(event, "state_key")
                and self._matches_regex(
                event.state_key, ApplicationService.NS_USERS)):
            return True
        return False

    def _matches_room_id(self, event):
        if hasattr(event, "room_id"):
            return self._matches_regex(
                event.room_id, ApplicationService.NS_ROOMS
            )
        return False

    def _matches_aliases(self, event, alias_list):
        for alias in alias_list:
            if self._matches_regex(alias, ApplicationService.NS_ALIASES):
                return True
        return False

    def is_interested(self, event, restrict_to=None, aliases_for_event=None):
        """Check if this service is interested in this event.

        Args:
            event(Event): The event to check.
            restrict_to(str): The namespace to restrict regex tests to.
            aliases_for_event(list): A list of all the known room aliases for
            this event.
        Returns:
            bool: True if this service would like to know about this event.
        """
        if aliases_for_event is None:
            aliases_for_event = []
        if restrict_to and restrict_to not in ApplicationService.NS_LIST:
            # this is a programming error, so fail early and raise a general
            # exception
            raise Exception("Unexpected restrict_to value: %s". restrict_to)

        if not restrict_to:
            return (self._matches_user(event)
                    or self._matches_aliases(event, aliases_for_event)
                    or self._matches_room_id(event))
        elif restrict_to == ApplicationService.NS_ALIASES:
            return self._matches_aliases(event, aliases_for_event)
        elif restrict_to == ApplicationService.NS_ROOMS:
            return self._matches_room_id(event)
        elif restrict_to == ApplicationService.NS_USERS:
            return self._matches_user(event)

    def __str__(self):
        return "ApplicationService: %s" % (self.__dict__,)
