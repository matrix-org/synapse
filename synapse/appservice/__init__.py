# Copyright 2015, 2016 OpenMarket Ltd
# Copyright 2022 The Matrix.org Foundation C.I.C.
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
from enum import Enum
from typing import TYPE_CHECKING, Dict, Iterable, List, Optional, Pattern

import attr
from netaddr import IPSet

from synapse.api.constants import EventTypes
from synapse.events import EventBase
from synapse.types import DeviceListUpdates, JsonDict, UserID
from synapse.util.caches.descriptors import _CacheContext, cached

if TYPE_CHECKING:
    from synapse.appservice.api import ApplicationServiceApi
    from synapse.storage.databases.main import DataStore

logger = logging.getLogger(__name__)

# Type for the `device_one_time_key_counts` field in an appservice transaction
#   user ID -> {device ID -> {algorithm -> count}}
TransactionOneTimeKeyCounts = Dict[str, Dict[str, Dict[str, int]]]

# Type for the `device_unused_fallback_key_types` field in an appservice transaction
#   user ID -> {device ID -> [algorithm]}
TransactionUnusedFallbackKeys = Dict[str, Dict[str, List[str]]]


class ApplicationServiceState(Enum):
    DOWN = "down"
    UP = "up"


@attr.s(slots=True, frozen=True, auto_attribs=True)
class Namespace:
    exclusive: bool
    regex: Pattern[str]


class ApplicationService:
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
        token: str,
        id: str,
        sender: str,
        url: Optional[str] = None,
        namespaces: Optional[JsonDict] = None,
        hs_token: Optional[str] = None,
        protocols: Optional[Iterable[str]] = None,
        rate_limited: bool = True,
        ip_range_whitelist: Optional[IPSet] = None,
        supports_ephemeral: bool = False,
        msc3202_transaction_extensions: bool = False,
    ):
        self.token = token
        self.url = (
            url.rstrip("/") if isinstance(url, str) else None
        )  # url must not end with a slash
        self.hs_token = hs_token
        self.sender = sender
        self.namespaces = self._check_namespaces(namespaces)
        self.id = id
        self.ip_range_whitelist = ip_range_whitelist
        self.supports_ephemeral = supports_ephemeral
        self.msc3202_transaction_extensions = msc3202_transaction_extensions

        if "|" in self.id:
            raise Exception("application service ID cannot contain '|' character")

        # .protocols is a publicly visible field
        if protocols:
            self.protocols = set(protocols)
        else:
            self.protocols = set()

        self.rate_limited = rate_limited

    def _check_namespaces(
        self, namespaces: Optional[JsonDict]
    ) -> Dict[str, List[Namespace]]:
        # Sanity check that it is of the form:
        # {
        #   users: [ {regex: "[A-z]+.*", exclusive: true}, ...],
        #   aliases: [ {regex: "[A-z]+.*", exclusive: true}, ...],
        #   rooms: [ {regex: "[A-z]+.*", exclusive: true}, ...],
        # }
        if namespaces is None:
            namespaces = {}

        result: Dict[str, List[Namespace]] = {}

        for ns in ApplicationService.NS_LIST:
            result[ns] = []

            if ns not in namespaces:
                continue

            if not isinstance(namespaces[ns], list):
                raise ValueError("Bad namespace value for '%s'" % ns)
            for regex_obj in namespaces[ns]:
                if not isinstance(regex_obj, dict):
                    raise ValueError("Expected dict regex for ns '%s'" % ns)
                exclusive = regex_obj.get("exclusive")
                if not isinstance(exclusive, bool):
                    raise ValueError("Expected bool for 'exclusive' in ns '%s'" % ns)

                regex = regex_obj.get("regex")
                if not isinstance(regex, str):
                    raise ValueError("Expected string for 'regex' in ns '%s'" % ns)

                # Pre-compile regex.
                result[ns].append(Namespace(exclusive, re.compile(regex)))

        return result

    def _matches_regex(
        self, namespace_key: str, test_string: str
    ) -> Optional[Namespace]:
        for namespace in self.namespaces[namespace_key]:
            if namespace.regex.match(test_string):
                return namespace
        return None

    def _is_exclusive(self, namespace_key: str, test_string: str) -> bool:
        namespace = self._matches_regex(namespace_key, test_string)
        if namespace:
            return namespace.exclusive
        return False

    @cached(num_args=1, cache_context=True)
    async def _matches_user_in_member_list(
        self,
        room_id: str,
        store: "DataStore",
        cache_context: _CacheContext,
    ) -> bool:
        """Check if this service is interested a room based upon its membership

        Args:
            room_id: The room to check.
            store: The datastore to query.

        Returns:
            True if this service would like to know about this room.
        """
        member_list = await store.get_users_in_room(
            room_id, on_invalidate=cache_context.invalidate
        )

        # check joined member events
        for user_id in member_list:
            if self.is_interested_in_user(user_id):
                return True
        return False

    def is_interested_in_user(
        self,
        user_id: str,
    ) -> bool:
        """
        Returns whether the application is interested in a given user ID.

        The appservice is considered to be interested in a user if either: the
        user ID is in the appservice's user namespace, or if the user is the
        appservice's configured sender_localpart.

        Args:
            user_id: The ID of the user to check.

        Returns:
            True if the application service is interested in the user, False if not.
        """
        return (
            # User is the appservice's sender_localpart user
            user_id == self.sender
            # User is in the appservice's user namespace
            or self.is_user_in_namespace(user_id)
        )

    @cached(num_args=1, cache_context=True)
    async def is_interested_in_room(
        self,
        room_id: str,
        store: "DataStore",
        cache_context: _CacheContext,
    ) -> bool:
        """
        Returns whether the application service is interested in a given room ID.

        The appservice is considered to be interested in the room if either: the ID or one
        of the aliases of the room is in the appservice's room ID or alias namespace
        respectively, or if one of the members of the room fall into the appservice's user
        namespace.

        Args:
            room_id: The ID of the room to check.
            store: The homeserver's datastore class.

        Returns:
            True if the application service is interested in the room, False if not.
        """
        # Check if we have interest in this room ID
        if self.is_room_id_in_namespace(room_id):
            return True

        # likewise with the room's aliases (if it has any)
        alias_list = await store.get_aliases_for_room(room_id)
        for alias in alias_list:
            if self.is_room_alias_in_namespace(alias):
                return True

        # And finally, perform an expensive check on whether any of the
        # users in the room match the appservice's user namespace
        return await self._matches_user_in_member_list(
            room_id, store, on_invalidate=cache_context.invalidate
        )

    @cached(num_args=1, cache_context=True)
    async def is_interested_in_event(
        self,
        event_id: str,
        event: EventBase,
        store: "DataStore",
        cache_context: _CacheContext,
    ) -> bool:
        """Check if this service is interested in this event.

        Args:
            event_id: The ID of the event to check. This is purely used for simplifying the
                caching of calls to this method.
            event: The event to check.
            store: The datastore to query.

        Returns:
            True if this service would like to know about this event, otherwise False.
        """
        # Check if we're interested in this event's sender by namespace (or if they're the
        # sender_localpart user)
        if self.is_interested_in_user(event.sender):
            return True

        # additionally, if this is a membership event, perform the same checks on
        # the user it references
        if event.type == EventTypes.Member and self.is_interested_in_user(
            event.state_key
        ):
            return True

        # This will check the datastore, so should be run last
        if await self.is_interested_in_room(
            event.room_id, store, on_invalidate=cache_context.invalidate
        ):
            return True

        return False

    @cached(num_args=1, cache_context=True)
    async def is_interested_in_presence(
        self, user_id: UserID, store: "DataStore", cache_context: _CacheContext
    ) -> bool:
        """Check if this service is interested a user's presence

        Args:
            user_id: The user to check.
            store: The datastore to query.

        Returns:
            True if this service would like to know about presence for this user.
        """
        # Find all the rooms the sender is in
        if self.is_interested_in_user(user_id.to_string()):
            return True
        room_ids = await store.get_rooms_for_user(user_id.to_string())

        # Then find out if the appservice is interested in any of those rooms
        for room_id in room_ids:
            if await self.is_interested_in_room(
                room_id, store, on_invalidate=cache_context.invalidate
            ):
                return True
        return False

    def is_user_in_namespace(self, user_id: str) -> bool:
        return bool(self._matches_regex(ApplicationService.NS_USERS, user_id))

    def is_room_alias_in_namespace(self, alias: str) -> bool:
        return bool(self._matches_regex(ApplicationService.NS_ALIASES, alias))

    def is_room_id_in_namespace(self, room_id: str) -> bool:
        return bool(self._matches_regex(ApplicationService.NS_ROOMS, room_id))

    def is_exclusive_user(self, user_id: str) -> bool:
        return (
            self._is_exclusive(ApplicationService.NS_USERS, user_id)
            or user_id == self.sender
        )

    def is_interested_in_protocol(self, protocol: str) -> bool:
        return protocol in self.protocols

    def is_exclusive_alias(self, alias: str) -> bool:
        return self._is_exclusive(ApplicationService.NS_ALIASES, alias)

    def is_exclusive_room(self, room_id: str) -> bool:
        return self._is_exclusive(ApplicationService.NS_ROOMS, room_id)

    def get_exclusive_user_regexes(self) -> List[Pattern[str]]:
        """Get the list of regexes used to determine if a user is exclusively
        registered by the AS
        """
        return [
            namespace.regex
            for namespace in self.namespaces[ApplicationService.NS_USERS]
            if namespace.exclusive
        ]

    def is_rate_limited(self) -> bool:
        return self.rate_limited

    def __str__(self) -> str:
        # copy dictionary and redact token fields so they don't get logged
        dict_copy = self.__dict__.copy()
        dict_copy["token"] = "<redacted>"
        dict_copy["hs_token"] = "<redacted>"
        return "ApplicationService: %s" % (dict_copy,)


class AppServiceTransaction:
    """Represents an application service transaction."""

    def __init__(
        self,
        service: ApplicationService,
        id: int,
        events: List[EventBase],
        ephemeral: List[JsonDict],
        to_device_messages: List[JsonDict],
        one_time_key_counts: TransactionOneTimeKeyCounts,
        unused_fallback_keys: TransactionUnusedFallbackKeys,
        device_list_summary: DeviceListUpdates,
    ):
        self.service = service
        self.id = id
        self.events = events
        self.ephemeral = ephemeral
        self.to_device_messages = to_device_messages
        self.one_time_key_counts = one_time_key_counts
        self.unused_fallback_keys = unused_fallback_keys
        self.device_list_summary = device_list_summary

    async def send(self, as_api: "ApplicationServiceApi") -> bool:
        """Sends this transaction using the provided AS API interface.

        Args:
            as_api: The API to use to send.
        Returns:
            True if the transaction was sent.
        """
        return await as_api.push_bulk(
            service=self.service,
            events=self.events,
            ephemeral=self.ephemeral,
            to_device_messages=self.to_device_messages,
            one_time_key_counts=self.one_time_key_counts,
            unused_fallback_keys=self.unused_fallback_keys,
            device_list_summary=self.device_list_summary,
            txn_id=self.id,
        )

    async def complete(self, store: "DataStore") -> None:
        """Completes this transaction as successful.

        Marks this transaction ID on the application service and removes the
        transaction contents from the database.

        Args:
            store: The database store to operate on.
        """
        await store.complete_appservice_txn(service=self.service, txn_id=self.id)
