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

from synapse.util.caches import register_cache


from blist import sorteddict
import logging
import os


logger = logging.getLogger(__name__)


CACHE_SIZE_FACTOR = float(os.environ.get("SYNAPSE_CACHE_FACTOR", 0.1))


class StreamChangeCache(object):
    """Keeps track of the stream positions of the latest change in a set of entities.

    Typically the entity will be a room or user id.

    Given a list of entities and a stream position, it will give a subset of
    entities that may have changed since that position. If position key is too
    old then the cache will simply return all given entities.
    """
    def __init__(self, name, current_stream_pos, max_size=10000, prefilled_cache={}):
        self._max_size = int(max_size * CACHE_SIZE_FACTOR)
        self._entity_to_key = {}
        self._cache = sorteddict()
        self._earliest_known_stream_pos = current_stream_pos
        self.name = name
        self.metrics = register_cache(self.name, self._cache)

        for entity, stream_pos in prefilled_cache.items():
            self.entity_has_changed(entity, stream_pos)

    def has_entity_changed(self, entity, stream_pos):
        """Returns True if the entity may have been updated since stream_pos
        """
        assert type(stream_pos) is int

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

    def get_entities_changed(self, entities, stream_pos):
        """Returns subset of entities that have had new things since the
        given position. If the position is too old it will just return the given list.
        """
        assert type(stream_pos) is int

        if stream_pos >= self._earliest_known_stream_pos:
            keys = self._cache.keys()
            i = keys.bisect_right(stream_pos)

            result = set(
                self._cache[k] for k in keys[i:]
            ).intersection(entities)

            self.metrics.inc_hits()
        else:
            result = entities
            self.metrics.inc_misses()

        return result

    def get_all_entities_changed(self, stream_pos):
        """Returns all entites that have had new things since the given
        position. If the position is too old it will return None.
        """
        assert type(stream_pos) is int

        if stream_pos >= self._earliest_known_stream_pos:
            keys = self._cache.keys()
            i = keys.bisect_right(stream_pos)

            return [self._cache[k] for k in keys[i:]]
        else:
            return None

    def entity_has_changed(self, entity, stream_pos):
        """Informs the cache that the entity has been changed at the given
        position.
        """
        assert type(stream_pos) is int

        if stream_pos > self._earliest_known_stream_pos:
            old_pos = self._entity_to_key.get(entity, None)
            if old_pos is not None:
                stream_pos = max(stream_pos, old_pos)
                self._cache.pop(old_pos, None)
            self._cache[stream_pos] = entity
            self._entity_to_key[entity] = stream_pos

            while len(self._cache) > self._max_size:
                k, r = self._cache.popitem()
                self._earliest_known_stream_pos = max(k, self._earliest_known_stream_pos)
                self._entity_to_key.pop(r, None)

    def get_max_pos_of_last_change(self, entity):
        """Returns an upper bound of the stream id of the last change to an
        entity.
        """
        return self._entity_to_key.get(entity, self._earliest_known_stream_pos)
