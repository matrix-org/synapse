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

from synapse.util.caches import cache_counter, caches_by_name


from blist import sorteddict
import logging


logger = logging.getLogger(__name__)


class RoomStreamChangeCache(object):
    """Keeps track of the stream_id of the latest change in rooms.

    Given a list of rooms and stream key, it will give a subset of rooms that
    may have changed since that key. If the key is too old then the cache
    will simply return all rooms.
    """
    def __init__(self, name, current_key, size_of_cache=10000):
        self._size_of_cache = size_of_cache
        self._room_to_key = {}
        self._cache = sorteddict()
        self._earliest_known_key = current_key
        self.name = name
        caches_by_name[self.name] = self._cache

    def get_room_has_changed(self, room_id, key):
        if key <= self._earliest_known_key:
            return True

        room_key = self._room_to_key.get(room_id, None)
        if room_key is None:
            return True

        if key < room_key:
            return True

        return False

    def get_rooms_changed(self, store, room_ids, key):
        """Returns subset of room ids that have had new things since the
        given key. If the key is too old it will just return the given list.
        """
        if key > self._earliest_known_key:
            keys = self._cache.keys()
            i = keys.bisect_right(key)

            result = set(
                self._cache[k] for k in keys[i:]
            ).intersection(room_ids)

            cache_counter.inc_hits(self.name)
        else:
            result = room_ids
            cache_counter.inc_misses(self.name)

        return result

    def room_has_changed(self, store, room_id, key):
        """Informs the cache that the room has been changed at the given key.
        """
        if key > self._earliest_known_key:
            old_key = self._room_to_key.get(room_id, None)
            if old_key:
                key = max(key, old_key)
                self._cache.pop(old_key, None)
            self._cache[key] = room_id

            while len(self._cache) > self._size_of_cache:
                k, r = self._cache.popitem()
                self._earliest_key = max(k, self._earliest_key)
                self._room_to_key.pop(r, None)
