# Copyright 2021 The Matrix.org Foundation C.I.C.
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
from typing import Generic, Optional, Protocol, TypeVar

import attr

logger = logging.getLogger(__name__)


class ListValue(Protocol):
    def drop(self) -> None:
        ...


V = TypeVar("V", bound=ListValue)


@attr.s(slots=True, auto_attribs=True)
class _ListNode(Generic[V]):
    value: Optional[V] = None
    prev_node: "_ListNode" = attr.Factory(lambda self: self, takes_self=True)
    next_node: "_ListNode" = attr.Factory(lambda self: self, takes_self=True)

    def delete_from_cache(self) -> None:
        if self.value is None:
            logger.warning("Tried delete list node from cache twice.")
            return

        self.value.drop()

    def remove_from_list(self) -> None:
        prev_node = self.prev_node
        next_node = self.next_node
        prev_node.next_node = next_node
        next_node.prev_node = prev_node

        self.value = None

    def move_node_to_front(self, list_root: "_ListNode") -> None:
        self.remove_from_list()

        prev_node = list_root
        next_node = prev_node.next_node

        self.prev_node = prev_node
        self.next_node = next_node

        prev_node.next_node = self
        next_node.prev_node = self


@attr.s(slots=True)
class LinkedList(Generic[V]):
    root: _ListNode[V] = attr.Factory(_ListNode)
