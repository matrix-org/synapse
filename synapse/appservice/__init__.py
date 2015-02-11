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

import logging
import re

logger = logging.getLogger(__name__)


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

    def __init__(self, token, url=None, namespaces=None, hs_token=None,
                 sender=None, txn_id=None):
        self.token = token
        self.url = url
        self.hs_token = hs_token
        self.sender = sender
        self.namespaces = self._check_namespaces(namespaces)
        self.txn_id = txn_id

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
        if not isinstance(test_string, basestring):
            logger.error(
                "Expected a string to test regex against, but got %s",
                test_string
            )
            return False

        for regex in self.namespaces[namespace_key]:
            if re.match(regex, test_string):
                return True
        return False

    def _matches_user(self, event, member_list):
        if (hasattr(event, "sender") and
                self.is_interested_in_user(event.sender)):
            return True
        # also check m.room.member state key
        if (hasattr(event, "type") and event.type == EventTypes.Member
                and hasattr(event, "state_key")
                and self.is_interested_in_user(event.state_key)):
            return True
        # check joined member events
        for member in member_list:
            if self.is_interested_in_user(member.state_key):
                return True
        return False

    def _matches_room_id(self, event):
        if hasattr(event, "room_id"):
            return self.is_interested_in_room(event.room_id)
        return False

    def _matches_aliases(self, event, alias_list):
        for alias in alias_list:
            if self.is_interested_in_alias(alias):
                return True
        return False

    def is_interested(self, event, restrict_to=None, aliases_for_event=None,
                      member_list=None):
        """Check if this service is interested in this event.

        Args:
            event(Event): The event to check.
            restrict_to(str): The namespace to restrict regex tests to.
            aliases_for_event(list): A list of all the known room aliases for
            this event.
            member_list(list): A list of all joined room members in this room.
        Returns:
            bool: True if this service would like to know about this event.
        """
        if aliases_for_event is None:
            aliases_for_event = []
        if member_list is None:
            member_list = []

        if restrict_to and restrict_to not in ApplicationService.NS_LIST:
            # this is a programming error, so fail early and raise a general
            # exception
            raise Exception("Unexpected restrict_to value: %s". restrict_to)

        if not restrict_to:
            return (self._matches_user(event, member_list)
                    or self._matches_aliases(event, aliases_for_event)
                    or self._matches_room_id(event))
        elif restrict_to == ApplicationService.NS_ALIASES:
            return self._matches_aliases(event, aliases_for_event)
        elif restrict_to == ApplicationService.NS_ROOMS:
            return self._matches_room_id(event)
        elif restrict_to == ApplicationService.NS_USERS:
            return self._matches_user(event, member_list)

    def is_interested_in_user(self, user_id):
        return self._matches_regex(user_id, ApplicationService.NS_USERS)

    def is_interested_in_alias(self, alias):
        return self._matches_regex(alias, ApplicationService.NS_ALIASES)

    def is_interested_in_room(self, room_id):
        return self._matches_regex(room_id, ApplicationService.NS_ROOMS)

    def __str__(self):
        return "ApplicationService: %s" % (self.__dict__,)
