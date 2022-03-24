# Copyright 2019 New Vector Ltd
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
from typing import TYPE_CHECKING, Any, Dict, List, Optional

import attr

from synapse.types import JsonDict

if TYPE_CHECKING:
    from synapse.storage.databases.main import DataStore

logger = logging.getLogger(__name__)


@attr.s(slots=True, auto_attribs=True)
class PaginationChunk:
    """Returned by relation pagination APIs.

    Attributes:
        chunk: The rows returned by pagination
        next_batch: Token to fetch next set of results with, if
            None then there are no more results.
        prev_batch: Token to fetch previous set of results with, if
            None then there are no previous results.
    """

    chunk: List[JsonDict]
    next_batch: Optional[Any] = None
    prev_batch: Optional[Any] = None

    async def to_dict(self, store: "DataStore") -> Dict[str, Any]:
        d = {"chunk": self.chunk}

        if self.next_batch:
            d["next_batch"] = await self.next_batch.to_string(store)

        if self.prev_batch:
            d["prev_batch"] = await self.prev_batch.to_string(store)

        return d
