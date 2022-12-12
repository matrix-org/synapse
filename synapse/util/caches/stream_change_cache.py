# Copyright 2016 OpenMarket Ltd
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
import math
from typing import Collection, Dict, FrozenSet, List, Mapping, Optional, Set, Union

import attr
from sortedcontainers import SortedDict

from synapse.util import caches

logger = logging.getLogger(__name__)

# for now, assume all entities in the cache are strings
EntityType = str


@attr.s(auto_attribs=True, frozen=True, slots=True)
class AllEntitiesChangedResult:
    """Return type of `get_all_entities_changed`.

    Callers must check that there was a cache hit, via `result.hit`, before
    using the entities in `result.entities`.

    This specifically does *not* implement helpers such as `__bool__` to ensure
    that callers do the correct checks.
    """

    _entities: Optional[List[EntityType]]

    @property
    def hit(self) -> bool:
        return self._entities is not None

    @property
    def entities(self) -> List[EntityType]:
        assert self._entities is not None
        return self._entities


class StreamChangeCache:
    """
    Keeps track of the stream positions of the latest change in a set of entities.

    The entity will is typically a room ID or user ID, but can be any string.

    Can be queried for whether a specific entity has changed after a stream position
    or for a list of changed entities after a stream position. See the individual
    methods for more information.

    Only tracks to a maximum cache size, any position earlier than the earliest
    known stream position must be treated as unknown.
    """

    def __init__(
        self,
        name: str,
        current_stream_pos: int,
        max_size: int = 10000,
        prefilled_cache: Optional[Mapping[EntityType, int]] = None,
    ) -> None:
        self._original_max_size: int = max_size
        self._max_size = math.floor(max_size)

        # map from stream id to the set of entities which changed at that stream id.
        self._cache: SortedDict[int, Set[EntityType]] = SortedDict()
        # map from entity to the stream ID of the latest change for that entity.
        #
        # Must be kept in sync with _cache.
        self._entity_to_key: Dict[EntityType, int] = {}

        # the earliest stream_pos for which we can reliably answer
        # get_all_entities_changed. In other words, one less than the earliest
        # stream_pos for which we know _cache is valid.
        #
        self._earliest_known_stream_pos = current_stream_pos

        self.name = name
        self.metrics = caches.register_cache(
            "cache", self.name, self._cache, resize_callback=self.set_cache_factor
        )

        if prefilled_cache:
            for entity, stream_pos in prefilled_cache.items():
                self.entity_has_changed(entity, stream_pos)

    def set_cache_factor(self, factor: float) -> bool:
        """
        Set the cache factor for this individual cache.

        This will trigger a resize if it changes, which may require evicting
        items from the cache.

        Returns:
            Whether the cache changed size or not.
        """
        new_size = math.floor(self._original_max_size * factor)
        if new_size != self._max_size:
            self.max_size = new_size
            self._evict()
            return True
        return False

    def has_entity_changed(self, entity: EntityType, stream_pos: int) -> bool:
        """
        Returns True if the entity may have been updated after stream_pos.

        Args:
            entity: The entity to check for changes.
            stream_pos: The stream position to check for changes after.

        Return:
            True if the entity may have been updated, this happens if:
                * The given stream position is at or earlier than the earliest
                  known stream position.
                * The given stream position is earlier than the latest change for
                  the entity.

            False otherwise:
                * The entity is unknown.
                * The given stream position is at or later than the latest change
                  for the entity.
        """
        assert isinstance(stream_pos, int)

        # _cache is not valid at or before the earliest known stream position, so
        # return that the entity has changed.
        if stream_pos <= self._earliest_known_stream_pos:
            self.metrics.inc_misses()
            return True

        # If the entity is unknown, it hasn't changed.
        latest_entity_change_pos = self._entity_to_key.get(entity, None)
        if latest_entity_change_pos is None:
            self.metrics.inc_hits()
            return False

        # This is a known entity, return true if the stream position is earlier
        # than the last change.
        if stream_pos < latest_entity_change_pos:
            self.metrics.inc_misses()
            return True

        # Otherwise, the stream position is after the latest change: return false.
        self.metrics.inc_hits()
        return False

    def get_entities_changed(
        self, entities: Collection[EntityType], stream_pos: int
    ) -> Union[Set[EntityType], FrozenSet[EntityType]]:
        """
        Returns the subset of the given entities that have had changes after the given position.

        Entities unknown to the cache will be returned.

        If the position is too old it will just return the given list.

        Args:
            entities: Entities to check for changes.
            stream_pos: The stream position to check for changes after.

        Return:
            A subset of entities which have changed after the given stream position.

            This will be all entities if the given stream position is at or earlier
            than the earliest known stream position.
        """
        cache_result = self.get_all_entities_changed(stream_pos)
        if cache_result.hit:
            # We now do an intersection, trying to do so in the most efficient
            # way possible (some of these sets are *large*). First check in the
            # given iterable is already a set that we can reuse, otherwise we
            # create a set of the *smallest* of the two iterables and call
            # `intersection(..)` on it (this can be twice as fast as the reverse).
            if isinstance(entities, (set, frozenset)):
                result = entities.intersection(cache_result.entities)
            elif len(cache_result.entities) < len(entities):
                result = set(cache_result.entities).intersection(entities)
            else:
                result = set(entities).intersection(cache_result.entities)
            self.metrics.inc_hits()
        else:
            result = set(entities)
            self.metrics.inc_misses()

        return result

    def has_any_entity_changed(self, stream_pos: int) -> bool:
        """
        Returns true if any entity has changed after the given stream position.

        Args:
            stream_pos: The stream position to check for changes after.

        Return:
            True if any entity has changed after the given stream position or
            if the given stream position is at or earlier than the earliest
            known stream position.

            False otherwise.
        """
        assert isinstance(stream_pos, int)

        # _cache is not valid at or before the earliest known stream position, so
        # return that an entity has changed.
        if stream_pos <= self._earliest_known_stream_pos:
            self.metrics.inc_misses()
            return True

        # If the cache is empty, nothing can have changed.
        if not self._cache:
            self.metrics.inc_misses()
            return False

        self.metrics.inc_hits()
        return stream_pos < self._cache.peekitem()[0]

    def get_all_entities_changed(self, stream_pos: int) -> AllEntitiesChangedResult:
        """
        Returns all entities that have had changes after the given position.

        If the stream change cache does not go far enough back, i.e. the
        position is too old, it will return None.

        Returns the entities in the order that they were changed.

        Args:
            stream_pos: The stream position to check for changes after.

        Return:
            A class indicating if we have the requested data cached, and if so
            includes the entities in the order they were changed.
        """
        assert isinstance(stream_pos, int)

        # _cache is not valid at or before the earliest known stream position, so
        # return None to mark that it is unknown if an entity has changed.
        if stream_pos <= self._earliest_known_stream_pos:
            return AllEntitiesChangedResult(None)

        changed_entities: List[EntityType] = []

        for k in self._cache.islice(start=self._cache.bisect_right(stream_pos)):
            changed_entities.extend(self._cache[k])
        return AllEntitiesChangedResult(changed_entities)

    def entity_has_changed(self, entity: EntityType, stream_pos: int) -> None:
        """
        Informs the cache that the entity has been changed at the given position.

        Args:
            entity: The entity to mark as changed.
            stream_pos: The stream position to update the entity to.
        """
        assert isinstance(stream_pos, int)

        # For a change before _cache is valid (e.g. at or before the earliest known
        # stream position) there's nothing to do.
        if stream_pos <= self._earliest_known_stream_pos:
            return

        old_pos = self._entity_to_key.get(entity, None)
        if old_pos is not None:
            if old_pos >= stream_pos:
                # nothing to do
                return
            e = self._cache[old_pos]
            e.remove(entity)
            if not e:
                # cache at this point is now empty
                del self._cache[old_pos]

        e1 = self._cache.get(stream_pos)
        if e1 is None:
            e1 = self._cache[stream_pos] = set()
        e1.add(entity)
        self._entity_to_key[entity] = stream_pos
        self._evict()

    def _evict(self) -> None:
        """
        Ensure the cache has not exceeded the maximum size.

        Evicts entries until it is at the maximum size.
        """
        # if the cache is too big, remove entries
        while len(self._cache) > self._max_size:
            k, r = self._cache.popitem(0)
            self._earliest_known_stream_pos = max(k, self._earliest_known_stream_pos)
            for entity in r:
                self._entity_to_key.pop(entity, None)

    def get_max_pos_of_last_change(self, entity: EntityType) -> int:
        """Returns an upper bound of the stream id of the last change to an
        entity.

        Args:
            entity: The entity to check.

        Return:
            The stream position of the latest change for the given entity or
            the earliest known stream position if the entitiy is unknown.
        """
        return self._entity_to_key.get(entity, self._earliest_known_stream_pos)
