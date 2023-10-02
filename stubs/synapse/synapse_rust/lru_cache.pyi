# Copyright 2023 The Matrix.org Foundation C.I.C.
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
from typing import Callable, Generic, List, Optional, Set, TypeVar, Collection

from synapse.util.caches.lrucache import LruCache

# Key and Value type for the cache
KT = TypeVar("KT")
VT = TypeVar("VT")

class LruCacheNode(Generic[KT, VT]):
    key: KT
    value: VT
    memory: int
    last_access_ts_secs: int

    def __init__(
        self,
        cache: LruCache,
        cache_list: "PerCacheLinkedList",
        key: object,
        value: object,
        callbacks: Set[Callable[[], None]],
        memory: int,
        ts_secs: int,
    ) -> None: ...
    def add_callbacks(self, new_callbacks: Collection[Callable[[], None]]) -> None: ...
    def run_and_clear_callbacks(self) -> None: ...
    def drop_from_cache(self) -> None: ...
    def drop_from_lists(self) -> None: ...
    def move_to_front(self, ts_secs: int) -> None: ...

class PerCacheLinkedList(Generic[KT, VT]):
    def __init__(self) -> None: ...
    def get_back(self) -> Optional[LruCacheNode[KT, VT]]: ...

def get_global_list() -> List[LruCacheNode]: ...
