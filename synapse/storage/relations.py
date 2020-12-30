# -*- coding: utf-8 -*-
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
from typing import Any, Dict, List, Optional, Tuple

import attr

from synapse.api.errors import SynapseError
from synapse.types import JsonDict

logger = logging.getLogger(__name__)


@attr.s(slots=True)
class PaginationChunk:
    """Returned by relation pagination APIs.

    Attributes:
        chunk: The rows returned by pagination
        next_batch: Token to fetch next set of results with, if
            None then there are no more results.
        prev_batch: Token to fetch previous set of results with, if
            None then there are no previous results.
    """

    chunk = attr.ib(type=List[JsonDict])
    next_batch = attr.ib(type=Optional[Any], default=None)
    prev_batch = attr.ib(type=Optional[Any], default=None)

    def to_dict(self) -> Dict[str, Any]:
        d = {"chunk": self.chunk}

        if self.next_batch:
            d["next_batch"] = self.next_batch.to_string()

        if self.prev_batch:
            d["prev_batch"] = self.prev_batch.to_string()

        return d


@attr.s(frozen=True, slots=True)
class RelationPaginationToken:
    """Pagination token for relation pagination API.

    As the results are in topological order, we can use the
    `topological_ordering` and `stream_ordering` fields of the events at the
    boundaries of the chunk as pagination tokens.

    Attributes:
        topological: The topological ordering of the boundary event
        stream: The stream ordering of the boundary event.
    """

    topological = attr.ib(type=int)
    stream = attr.ib(type=int)

    @staticmethod
    def from_string(string: str) -> "RelationPaginationToken":
        try:
            t, s = string.split("-")
            return RelationPaginationToken(int(t), int(s))
        except ValueError:
            raise SynapseError(400, "Invalid token")

    def to_string(self) -> str:
        return "%d-%d" % (self.topological, self.stream)

    def as_tuple(self) -> Tuple[Any, ...]:
        return attr.astuple(self)


@attr.s(frozen=True, slots=True)
class AggregationPaginationToken:
    """Pagination token for relation aggregation pagination API.

    As the results are order by count and then MAX(stream_ordering) of the
    aggregation groups, we can just use them as our pagination token.

    Attributes:
        count: The count of relations in the boundary group.
        stream: The MAX stream ordering in the boundary group.
    """

    count = attr.ib(type=int)
    stream = attr.ib(type=int)

    @staticmethod
    def from_string(string: str) -> "AggregationPaginationToken":
        try:
            c, s = string.split("-")
            return AggregationPaginationToken(int(c), int(s))
        except ValueError:
            raise SynapseError(400, "Invalid token")

    def to_string(self) -> str:
        return "%d-%d" % (self.count, self.stream)

    def as_tuple(self) -> Tuple[Any, ...]:
        return attr.astuple(self)
