# Copyright 2016-2021 The Matrix.org Foundation C.I.C.
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

from enum import Enum
from typing import (
    Any,
    Dict,
    Generator,
    Generic,
    List,
    Literal,
    Optional,
    Tuple,
    TypeVar,
    Union,
    overload,
)


class Sentinel(Enum):
    sentinel = object()


V = TypeVar("V")
T = TypeVar("T")


class TreeCacheNode(Generic[V]):
    """The type of nodes in our tree.

    Either a leaf node or a branch node.
    """

    __slots__ = ["leaf_value", "sub_tree"]

    def __init__(
        self,
        leaf_value: Union[V, Literal[Sentinel.sentinel]] = Sentinel.sentinel,
        sub_tree: Optional[Dict[Any, "TreeCacheNode[V]"]] = None,
    ) -> None:
        if leaf_value is Sentinel.sentinel and sub_tree is None:
            raise Exception("One of leaf or sub tree must be set")

        self.leaf_value: Union[V, Literal[Sentinel.sentinel]] = leaf_value
        self.sub_tree: Optional[Dict[Any, "TreeCacheNode[V]"]] = sub_tree

    @staticmethod
    def leaf(value: V) -> "TreeCacheNode[V]":
        return TreeCacheNode(leaf_value=value)

    @staticmethod
    def empty_branch() -> "TreeCacheNode[V]":
        return TreeCacheNode(sub_tree={})


class TreeCache(Generic[V]):
    """
    Tree-based backing store for LruCache. Allows subtrees of data to be deleted
    efficiently.
    Keys must be tuples.

    The data structure is a chain of TreeCacheNodes:
        root = {key_1: {key_2: _value}}
    """

    def __init__(self) -> None:
        self.size: int = 0
        self.root: TreeCacheNode[V] = TreeCacheNode.empty_branch()

    def __setitem__(self, key: tuple, value: V) -> None:
        self.set(key, value)

    def __contains__(self, key: tuple) -> bool:
        return self.get(key, None) is not None

    def set(self, key: tuple, value: V) -> None:
        if isinstance(value, TreeCacheNode):
            # this would mean we couldn't tell where our tree ended and the value
            # started.
            raise ValueError("Cannot store TreeCacheNodes in a TreeCache")

        node = self.root
        for k in key[:-1]:
            sub_tree = node.sub_tree
            if sub_tree is None:
                raise ValueError("value conflicts with an existing subtree")

            next_node = sub_tree.get(k, None)
            if next_node is None:
                node = TreeCacheNode.empty_branch()
                sub_tree[k] = node
            else:
                node = next_node

        if node.sub_tree is None:
            raise ValueError("value conflicts with an existing subtree")

        node.sub_tree[key[-1]] = TreeCacheNode.leaf(value)
        self.size += 1

    @overload
    def get(self, key: tuple, default: Literal[None] = None) -> Union[None, V]:
        ...

    @overload
    def get(self, key: tuple, default: T) -> Union[T, V]:
        ...

    def get(self, key: tuple, default: Optional[T] = None) -> Union[None, T, V]:
        node = self.root
        for k in key:
            sub_tree = node.sub_tree
            if sub_tree is None:
                raise ValueError("get() key too long")

            next_node = sub_tree.get(k, None)
            if next_node is None:
                return default

            node = next_node

        if node.leaf_value is Sentinel.sentinel:
            raise ValueError("key points to a branch")

        return node.leaf_value

    def clear(self) -> None:
        self.size = 0
        self.root = TreeCacheNode()

    def pop(
        self, key: tuple, default: Optional[T] = None
    ) -> Union[None, T, V, TreeCacheNode[V]]:
        """Remove the given key, or subkey, from the cache

        Args:
            key: key or subkey to remove.
            default: value to return if key is not found

        Returns:
            If the key is not found, 'default'. If the key is complete, the removed
            value. If the key is partial, the TreeCacheNode corresponding to the part
            of the tree that was removed.
        """
        if not isinstance(key, tuple):
            raise TypeError("The cache key must be a tuple not %r" % (type(key),))

        # a list of the nodes we have touched on the way down the tree
        nodes: List[TreeCacheNode[V]] = []

        node = self.root
        for k in key[:-1]:
            sub_tree = node.sub_tree
            if sub_tree is None:
                raise ValueError("pop() key too long")

            next_node = sub_tree.get(k, None)
            if next_node is None:
                return default

            node = next_node
            nodes.append(node)

        if node.sub_tree is None:
            raise ValueError("pop() key too long")

        popped = node.sub_tree.pop(key[-1])

        # working back up the tree, clear out any nodes that are now empty
        node_and_keys = list(zip(nodes, key))
        node_and_keys.reverse()
        node_and_keys.append((self.root, None))

        for i in range(len(node_and_keys) - 1):
            n, k = node_and_keys[i]

            if n:
                break

            # found an empty node: remove it from its parent, and loop.
            node = node_and_keys[i + 1][0]

            # We added it to the list so already know its a branch node.
            assert node.sub_tree is not None
            node.sub_tree.pop(k)

        cnt = sum(1 for _ in iterate_tree_cache_entry(popped))
        self.size -= cnt
        return popped

    def values(self):
        return iterate_tree_cache_entry(self.root)

    def __len__(self) -> int:
        return self.size


def iterate_tree_cache_entry(d: TreeCacheNode[V]) -> Generator[V, None, None]:
    """Helper function to iterate over the leaves of a tree, i.e. a dict of that
    can contain dicts.
    """

    if d.sub_tree is not None:
        for value_d in d.sub_tree.values():
            yield from iterate_tree_cache_entry(value_d)
    else:
        assert d.leaf_value is not Sentinel.sentinel
        yield d.leaf_value


def iterate_tree_cache_items(
    key: tuple, value: TreeCacheNode[V]
) -> Generator[Tuple[tuple, V], None, None]:
    """Helper function to iterate over the leaves of a tree, i.e. a dict of that
    can contain dicts.

    Returns:
        A generator yielding key/value pairs.
    """
    if value.sub_tree is not None:
        for sub_key, sub_value in value.sub_tree.items():
            yield from iterate_tree_cache_items((*key, sub_key), sub_value)
    else:
        assert value.leaf_value is not Sentinel.sentinel
        yield key, value.leaf_value
