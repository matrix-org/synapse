# -*- coding: utf-8 -*-
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
from typing import Dict, FrozenSet, List, Mapping, Optional, Set, Union

from six import integer_types

from sortedcontainers import SortedDict

from synapse.types import Collection
from synapse.util import caches

logger = logging.getLogger(__name__)

# for now, assume all entities in the cache are strings
EntityType = str


class StreamChangeCache:
    """Keeps track of the stream positions of the latest change in a set of entities.

    Typically the entity will be a room or user id.

    Given a list of entities and a stream position, it will give a subset of
    entities that may have changed since that position. If position key is too
    old then the cache will simply return all given entities.
    """

    def __init__(
        self,
        name: str,
        current_stream_pos: int,
        max_size=10000,
        prefilled_cache: Optional[Mapping[EntityType, int]] = None,
    ):
        self._original_max_size = max_size
        self._max_size = math.floor(max_size)
        self._entity_to_key = {}  # type: Dict[EntityType, int]

        # map from stream id to the a set of entities which changed at that stream id.
        self._cache = SortedDict()  # type: SortedDict[int, Set[EntityType]]

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
            bool: Whether the cache changed size or not.
        """
        new_size = math.floor(self._original_max_size * factor)
        if new_size != self._max_size:
            self.max_size = new_size
            self._evict()
            return True
        return False

    def has_entity_changed(self, entity: EntityType, stream_pos: int) -> bool:
        """Returns True if the entity may have been updated since stream_pos
        """
        assert type(stream_pos) in integer_types

        if stream_pos < self._earliest_known_stream_pos:
            self.metrics.inc_misses()
            return True

        latest_entity_change_pos = self._entity_to_key.get(entity, None)
        if latest_entity_change_pos is None:
            self.metrics.inc_hits()
            return False

        if stream_pos < latest_entity_change_pos:
            self.metrics.inc_misses()
            return True

        self.metrics.inc_hits()
        return False

    def get_entities_changed(
        self, entities: Collection[EntityType], stream_pos: int
    ) -> Union[Set[EntityType], FrozenSet[EntityType]]:
        """
        Returns subset of entities that have had new things since the given
        position.  Entities unknown to the cache will be returned.  If the
        position is too old it will just return the given list.
        """
        changed_entities = self.get_all_entities_changed(stream_pos)
        if changed_entities is not None:
            # We now do an intersection, trying to do so in the most efficient
            # way possible (some of these sets are *large*). First check in the
            # given iterable is already set that we can reuse, otherwise we
            # create a set of the *smallest* of the two iterables and call
            # `intersection(..)` on it (this can be twice as fast as the reverse).
            if isinstance(entities, (set, frozenset)):
                result = entities.intersection(changed_entities)
            elif len(changed_entities) < len(entities):
                result = set(changed_entities).intersection(entities)
            else:
                result = set(entities).intersection(changed_entities)
            self.metrics.inc_hits()
        else:
            result = set(entities)
            self.metrics.inc_misses()

        return result

    def has_any_entity_changed(self, stream_pos: int) -> bool:
        """Returns if any entity has changed
        """
        assert type(stream_pos) is int

        if not self._cache:
            # If the cache is empty, nothing can have changed.
            return False

        if stream_pos >= self._earliest_known_stream_pos:
            self.metrics.inc_hits()
            return self._cache.bisect_right(stream_pos) < len(self._cache)
        else:
            self.metrics.inc_misses()
            return True

    def get_all_entities_changed(self, stream_pos: int) -> Optional[List[EntityType]]:
        """Returns all entities that have had new things since the given
        position. If the position is too old it will return None.

        Returns the entities in the order that they were changed.
        """
        assert type(stream_pos) is int

        if stream_pos < self._earliest_known_stream_pos:
            return None

        changed_entities = []  # type: List[EntityType]

        for k in self._cache.islice(start=self._cache.bisect_right(stream_pos)):
            changed_entities.extend(self._cache[k])
        return changed_entities

    def entity_has_changed(self, entity: EntityType, stream_pos: int) -> None:
        """Informs the cache that the entity has been changed at the given
        position.
        """
        assert type(stream_pos) is int

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

        # if the cache is too big, remove entries
        while len(self._cache) > self._max_size:
            k, r = self._cache.popitem(0)
            self._earliest_known_stream_pos = max(k, self._earliest_known_stream_pos)
            for entity in r:
                del self._entity_to_key[entity]

    def _evict(self):
        while len(self._cache) > self._max_size:
            k, r = self._cache.popitem(0)
            self._earliest_known_stream_pos = max(k, self._earliest_known_stream_pos)
            for entity in r:
                self._entity_to_key.pop(entity, None)

    def get_max_pos_of_last_change(self, entity: EntityType) -> int:

        """Returns an upper bound of the stream id of the last change to an
        entity.
        """
        return self._entity_to_key.get(entity, self._earliest_known_stream_pos)
