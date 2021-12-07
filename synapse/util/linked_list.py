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

"""A circular doubly linked list implementation.
"""

import threading
from typing import Generic, Optional, Type, TypeVar

P = TypeVar("P")
LN = TypeVar("LN", bound="ListNode")


class ListNode(Generic[P]):
    """A node in a circular doubly linked list, with an (optional) reference to
    a cache entry.

    The reference should only be `None` for the root node or if the node has
    been removed from the list.
    """

    # A lock to protect mutating the list prev/next pointers.
    _LOCK = threading.Lock()

    # We don't use attrs here as in py3.6 you can't have `attr.s(slots=True)`
    # and inherit from `Generic` for some reason
    __slots__ = [
        "cache_entry",
        "prev_node",
        "next_node",
    ]

    def __init__(self, cache_entry: Optional[P] = None) -> None:
        self.cache_entry = cache_entry
        self.prev_node: Optional[ListNode[P]] = None
        self.next_node: Optional[ListNode[P]] = None

    @classmethod
    def create_root_node(cls: Type["ListNode[P]"]) -> "ListNode[P]":
        """Create a new linked list by creating a "root" node, which is a node
        that has prev_node/next_node pointing to itself and no associated cache
        entry.
        """
        root = cls()
        root.prev_node = root
        root.next_node = root
        return root

    @classmethod
    def insert_after(
        cls: Type[LN],
        cache_entry: P,
        node: "ListNode[P]",
    ) -> LN:
        """Create a new list node that is placed after the given node.

        Args:
            cache_entry: The associated cache entry.
            node: The existing node in the list to insert the new entry after.
        """
        new_node = cls(cache_entry)
        with cls._LOCK:
            new_node._refs_insert_after(node)
        return new_node

    def remove_from_list(self) -> None:
        """Remove this node from the list."""
        with self._LOCK:
            self._refs_remove_node_from_list()

        # We drop the reference to the cache entry to break the reference cycle
        # between the list node and cache entry, allowing the two to be dropped
        # immediately rather than at the next GC.
        self.cache_entry = None

    def move_after(self, node: "ListNode[P]") -> None:
        """Move this node from its current location in the list to after the
        given node.
        """
        with self._LOCK:
            # We assert that both this node and the target node is still "alive".
            assert self.prev_node
            assert self.next_node
            assert node.prev_node
            assert node.next_node

            assert self is not node

            # Remove self from the list
            self._refs_remove_node_from_list()

            # Insert self back into the list, after target node
            self._refs_insert_after(node)

    def _refs_remove_node_from_list(self) -> None:
        """Internal method to *just* remove the node from the list, without
        e.g. clearing out the cache entry.
        """
        if self.prev_node is None or self.next_node is None:
            # We've already been removed from the list.
            return

        prev_node = self.prev_node
        next_node = self.next_node

        prev_node.next_node = next_node
        next_node.prev_node = prev_node

        # We set these to None so that we don't get circular references,
        # allowing us to be dropped without having to go via the GC.
        self.prev_node = None
        self.next_node = None

    def _refs_insert_after(self, node: "ListNode[P]") -> None:
        """Internal method to insert the node after the given node."""

        # This method should only be called when we're not already in the list.
        assert self.prev_node is None
        assert self.next_node is None

        # We expect the given node to be in the list and thus have valid
        # prev/next refs.
        assert node.next_node
        assert node.prev_node

        prev_node = node
        next_node = node.next_node

        self.prev_node = prev_node
        self.next_node = next_node

        prev_node.next_node = self
        next_node.prev_node = self

    def get_cache_entry(self) -> Optional[P]:
        """Get the cache entry, returns None if this is the root node (i.e.
        cache_entry is None) or if the entry has been dropped.
        """
        return self.cache_entry
