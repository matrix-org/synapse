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
import logging
import re

from six import string_types

from twisted.internet import defer

from synapse.api.constants import EventTypes
from synapse.types import GroupID, get_domain_from_id
from synapse.util.caches.descriptors import cachedInlineCallbacks

logger = logging.getLogger(__name__)


class ApplicationServiceState(object):
    DOWN = "down"
    UP = "up"


class AppServiceTransaction(object):
    """Represents an application service transaction."""

    def __init__(self, service, id, events):
        self.service = service
        self.id = id
        self.events = events

    def send(self, as_api):
        """Sends this transaction using the provided AS API interface.

        Args:
            as_api(ApplicationServiceApi): The API to use to send.
        Returns:
            A Deferred which resolves to True if the transaction was sent.
        """
        return as_api.push_bulk(
            service=self.service, events=self.events, txn_id=self.id
        )

    def complete(self, store):
        """Completes this transaction as successful.

        Marks this transaction ID on the application service and removes the
        transaction contents from the database.

        Args:
            store: The database store to operate on.
        Returns:
            A Deferred which resolves to True if the transaction was completed.
        """
        return store.complete_appservice_txn(service=self.service, txn_id=self.id)


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

    def __init__(
        self,
        token,
        hostname,
        url=None,
        namespaces=None,
        hs_token=None,
        sender=None,
        id=None,
        protocols=None,
        rate_limited=True,
        ip_range_whitelist=None,
    ):
        self.token = token
        self.url = (
            url.rstrip("/") if isinstance(url, str) else None
        )  # url must not end with a slash
        self.hs_token = hs_token
        self.sender = sender
        self.server_name = hostname
        self.namespaces = self._check_namespaces(namespaces)
        self.id = id
        self.ip_range_whitelist = ip_range_whitelist

        if "|" in self.id:
            raise Exception("application service ID cannot contain '|' character")

        # .protocols is a publicly visible field
        if protocols:
            self.protocols = set(protocols)
        else:
            self.protocols = set()

        self.rate_limited = rate_limited

    def _check_namespaces(self, namespaces):
        # Sanity check that it is of the form:
        # {
        #   users: [ {regex: "[A-z]+.*", exclusive: true}, ...],
        #   aliases: [ {regex: "[A-z]+.*", exclusive: true}, ...],
        #   rooms: [ {regex: "[A-z]+.*", exclusive: true}, ...],
        # }
        if not namespaces:
            namespaces = {}

        for ns in ApplicationService.NS_LIST:
            if ns not in namespaces:
                namespaces[ns] = []
                continue

            if type(namespaces[ns]) != list:
                raise ValueError("Bad namespace value for '%s'" % ns)
            for regex_obj in namespaces[ns]:
                if not isinstance(regex_obj, dict):
                    raise ValueError("Expected dict regex for ns '%s'" % ns)
                if not isinstance(regex_obj.get("exclusive"), bool):
                    raise ValueError("Expected bool for 'exclusive' in ns '%s'" % ns)
                group_id = regex_obj.get("group_id")
                if group_id:
                    if not isinstance(group_id, str):
                        raise ValueError(
                            "Expected string for 'group_id' in ns '%s'" % ns
                        )
                    try:
                        GroupID.from_string(group_id)
                    except Exception:
                        raise ValueError(
                            "Expected valid group ID for 'group_id' in ns '%s'" % ns
                        )

                    if get_domain_from_id(group_id) != self.server_name:
                        raise ValueError(
                            "Expected 'group_id' to be this host in ns '%s'" % ns
                        )

                regex = regex_obj.get("regex")
                if isinstance(regex, string_types):
                    regex_obj["regex"] = re.compile(regex)  # Pre-compile regex
                else:
                    raise ValueError("Expected string for 'regex' in ns '%s'" % ns)
        return namespaces

    def _matches_regex(self, test_string, namespace_key):
        for regex_obj in self.namespaces[namespace_key]:
            if regex_obj["regex"].match(test_string):
                return regex_obj
        return None

    def _is_exclusive(self, ns_key, test_string):
        regex_obj = self._matches_regex(test_string, ns_key)
        if regex_obj:
            return regex_obj["exclusive"]
        return False

    @defer.inlineCallbacks
    def _matches_user(self, event, store):
        if not event:
            return False

        if self.is_interested_in_user(event.sender):
            return True
        # also check m.room.member state key
        if event.type == EventTypes.Member and self.is_interested_in_user(
            event.state_key
        ):
            return True

        if not store:
            return False

        does_match = yield self._matches_user_in_member_list(event.room_id, store)
        return does_match

    @cachedInlineCallbacks(num_args=1, cache_context=True)
    def _matches_user_in_member_list(self, room_id, store, cache_context):
        member_list = yield store.get_users_in_room(
            room_id, on_invalidate=cache_context.invalidate
        )

        # check joined member events
        for user_id in member_list:
            if self.is_interested_in_user(user_id):
                return True
        return False

    def _matches_room_id(self, event):
        if hasattr(event, "room_id"):
            return self.is_interested_in_room(event.room_id)
        return False

    @defer.inlineCallbacks
    def _matches_aliases(self, event, store):
        if not store or not event:
            return False

        alias_list = yield store.get_aliases_for_room(event.room_id)
        for alias in alias_list:
            if self.is_interested_in_alias(alias):
                return True
        return False

    @defer.inlineCallbacks
    def is_interested(self, event, store=None):
        """Check if this service is interested in this event.

        Args:
            event(Event): The event to check.
            store(DataStore)
        Returns:
            bool: True if this service would like to know about this event.
        """
        # Do cheap checks first
        if self._matches_room_id(event):
            return True

        if (yield self._matches_aliases(event, store)):
            return True

        if (yield self._matches_user(event, store)):
            return True

        return False

    def is_interested_in_user(self, user_id):
        return (
            self._matches_regex(user_id, ApplicationService.NS_USERS)
            or user_id == self.sender
        )

    def is_interested_in_alias(self, alias):
        return bool(self._matches_regex(alias, ApplicationService.NS_ALIASES))

    def is_interested_in_room(self, room_id):
        return bool(self._matches_regex(room_id, ApplicationService.NS_ROOMS))

    def is_exclusive_user(self, user_id):
        return (
            self._is_exclusive(ApplicationService.NS_USERS, user_id)
            or user_id == self.sender
        )

    def is_interested_in_protocol(self, protocol):
        return protocol in self.protocols

    def is_exclusive_alias(self, alias):
        return self._is_exclusive(ApplicationService.NS_ALIASES, alias)

    def is_exclusive_room(self, room_id):
        return self._is_exclusive(ApplicationService.NS_ROOMS, room_id)

    def get_exclusive_user_regexes(self):
        """Get the list of regexes used to determine if a user is exclusively
        registered by the AS
        """
        return [
            regex_obj["regex"]
            for regex_obj in self.namespaces[ApplicationService.NS_USERS]
            if regex_obj["exclusive"]
        ]

    def get_groups_for_user(self, user_id):
        """Get the groups that this user is associated with by this AS

        Args:
            user_id (str): The ID of the user.

        Returns:
            iterable[str]: an iterable that yields group_id strings.
        """
        return (
            regex_obj["group_id"]
            for regex_obj in self.namespaces[ApplicationService.NS_USERS]
            if "group_id" in regex_obj and regex_obj["regex"].match(user_id)
        )

    def is_rate_limited(self):
        return self.rate_limited

    def __str__(self):
        # copy dictionary and redact token fields so they don't get logged
        dict_copy = self.__dict__.copy()
        dict_copy["token"] = "<redacted>"
        dict_copy["hs_token"] = "<redacted>"
        return "ApplicationService: %s" % (dict_copy,)
