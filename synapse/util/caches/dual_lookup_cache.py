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
from typing import (
    Callable,
    Dict,
    Generic,
    ItemsView,
    Optional,
    Set,
    TypeVar,
    ValuesView,
)

SENTINEL = object()

# The type of the primary dict's keys.
PKT = TypeVar("PKT")
# The type of the primary dict's values.
PVT = TypeVar("PVT")
# The type of the secondary dict's keys.
SKT = TypeVar("SKT")

logger = logging.getLogger(__name__)


class DualLookupCache(Generic[PKT, PVT, SKT]):
    """
    A backing store for LruCache that supports multiple entry points.
    Allows subsets of data to be deleted efficiently without requiring extra
    information to query.

    The data structure is two dictionaries:
        * primary_dict containing a mapping of primary_key -> value.
        * secondary_dict containing a mapping of secondary_key -> set of primary_key.

    On insert, a mapping in the primary_dict must be created. A mapping in the
    secondary_dict from a secondary_key to (a set containing) the same
    primary_key will be made. The secondary_key
    must be derived from the inserted value via a lambda function provided at cache
    initialisation. This is so invalidated entries in the primary_dict may automatically
    invalidate those in the secondary_dict. The secondary_key may be associated with one
    or more primary_key's.

    This creates an interface which allows for efficient lookups of a value given
    a primary_key, as well as efficient invalidation of a subset of mapping in the
    primary_dict given a secondary_key. A primary_key may not be associated with more
    than one secondary_key.

    As a worked example, consider storing a cache of room events. We could configure
    the cache to store mappings between EventIDs and EventBase in the primary_dict,
    while storing a mapping between room IDs and event IDs as the secondary_dict:

        primary_dict: EventID -> EventBase
        secondary_dict: RoomID -> {EventID, EventID, ...}

    This would be efficient for the following operations:
        * Given an EventID, look up the associated EventBase, and thus the roomID.
        * Given a RoomID, invalidate all primary_dict entries for events in that room.

    Since this is intended as a backing store for LRUCache, when it came time to evict
    an entry from the primary_dict (EventID -> EventBase), the secondary_key could be
    derived from a provided lambda function:
        secondary_key = lambda event_base: event_base.room_id

    The EventID set under room_id would then have the appropriate EventID entry evicted.
    """

    def __init__(self, secondary_key_function: Callable[[PVT], SKT]) -> None:
        self._primary_dict: Dict[PKT, PVT] = {}
        self._secondary_dict: Dict[SKT, Set[PKT]] = {}
        self._secondary_key_function = secondary_key_function

    def __setitem__(self, key: PKT, value: PVT) -> None:
        self.set(key, value)

    def __contains__(self, key: PKT) -> bool:
        return key in self._primary_dict

    def set(self, key: PKT, value: PVT) -> None:
        """Add an entry to the cache.

        Will add an entry to the primary_dict consisting of key->value, as well as append
        to the set referred to by secondary_key_function(value) in the secondary_dict.

        Args:
            key: The key for a new mapping in primary_dict.
            value: The value for a new mapping in primary_dict.
        """
        # Create an entry in the primary_dict.
        self._primary_dict[key] = value

        # Derive the secondary_key to use from the given primary_value.
        secondary_key = self._secondary_key_function(value)

        # TODO: If the lambda function resolves to None, don't insert an entry?

        # And create a mapping in the secondary_dict to a set containing the
        # primary_key, creating the set if necessary.
        secondary_key_set = self._secondary_dict.setdefault(secondary_key, set())
        secondary_key_set.add(key)

        logger.info("*** Insert into primary_dict: %s: %s", key, value)
        logger.info("*** Insert into secondary_dict: %s: %s", secondary_key, key)

    def get(self, key: PKT, default: Optional[PVT] = None) -> Optional[PVT]:
        """Retrieve a value from the cache if it exists. If not, return the default
        value.

        This method simply pulls entries from the primary_dict.

        # TODO: Any use cases for externally getting entries from the secondary_dict?

        Args:
            key: The key to search the cache for.
            default: The default value to return if the given key is not found.

        Returns:
            The value referenced by the given key, if it exists in the cache. If not,
            the value of `default` will be returned.
        """
        logger.info("*** Retrieving key from primary_dict: %s", key)
        return self._primary_dict.get(key, default)

    def clear(self) -> None:
        """Evicts all entries from the cache."""
        self._primary_dict.clear()
        self._secondary_dict.clear()

    def pop(self, key: PKT, default: Optional[PVT] = None) -> Optional[PVT]:
        """Remove the given key, from the cache if it exists, and return the associated
        value.

        Evicts an entry from both the primary_dict and secondary_dict.

        Args:
            key: The key to remove from the cache.
            default: The value to return if the given key is not found.

        Returns:
            The value associated with the given key if it is found. Otherwise, the value
            of `default`.
        """
        # Exit immediately if the key is not found
        if key not in self._primary_dict:
            return default

        # Pop the entry from the primary_dict to retrieve the desired value
        primary_value = self._primary_dict.pop(key)

        logger.info("*** Popping from primary_dict: %s: %s", key, primary_value)

        # Derive the secondary_key from the primary_value
        secondary_key = self._secondary_key_function(primary_value)

        # Pop the entry from the secondary_dict
        secondary_key_set = self._secondary_dict[secondary_key]
        if len(secondary_key_set) > 1:
            # Delete just the set entry for the given key.
            secondary_key_set.remove(key)
            logger.info("*** Popping from secondary_dict: %s: %s", secondary_key, key)

        else:
            # Delete the entire soon-to-be-empty set referenced by the secondary_key.
            del self._secondary_dict[secondary_key]
            logger.info("*** Popping from secondary_dict: %s", secondary_key)

        return primary_value

    def del_multi(self, secondary_key: SKT) -> None:
        """Remove an entry from the secondary_dict, removing all associated entries
        in the primary_dict as well.

        Args:
            secondary_key: A secondary_key to drop. May be associated with zero or more
                primary keys. If any associated primary keys are found, they will be
                dropped as well.
        """
        primary_key_set = self._secondary_dict.pop(secondary_key, None)
        if not primary_key_set:
            logger.info(
                "*** Did not find '%s' in secondary_dict: %s",
                secondary_key,
                self._secondary_dict,
            )
            return

        logger.info("*** Popping whole key from secondary_dict: %s", secondary_key)
        for primary_key in primary_key_set:
            logger.info("*** Popping entry from primary_dict: %s", primary_key)
            logger.info("*** primary_dict: %s", self._primary_dict)
            del self._primary_dict[primary_key]

    def values(self) -> ValuesView:
        return self._primary_dict.values()

    def items(self) -> ItemsView:
        return self._primary_dict.items()

    def __len__(self) -> int:
        return len(self._primary_dict)
