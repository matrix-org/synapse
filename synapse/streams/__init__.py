# Copyright 2014-2016 OpenMarket Ltd
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

from typing import Collection, Generic, List, Optional, Tuple, TypeVar

from synapse.types import UserID

# The key, this is either a stream token or int.
K = TypeVar("K")
# The return type.
R = TypeVar("R")


class EventSource(Generic[K, R]):
    async def get_new_events(
        self,
        user: UserID,
        from_key: K,
        limit: Optional[int],
        room_ids: Collection[str],
        is_guest: bool,
        explicit_room_id: Optional[str] = None,
    ) -> Tuple[List[R], K]:
        ...
