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

SENTINEL = object()


class TreeCacheNode(dict):
    """The type of nodes in our tree.

    Has its own type so we can distinguish it from real dicts that are stored at the
    leaves.
    """


class TreeCache:
    """
    Tree-based backing store for LruCache. Allows subtrees of data to be deleted
    efficiently.
    Keys must be tuples.

    The data structure is a chain of TreeCacheNodes:
        root = {key_1: {key_2: _value}}
    """

    def __init__(self) -> None:
        self.size: int = 0
        self.root = TreeCacheNode()

    def __setitem__(self, key, value) -> None:
        self.set(key, value)

    def __contains__(self, key) -> bool:
        return self.get(key, SENTINEL) is not SENTINEL

    def set(self, key, value) -> None:
        if isinstance(value, TreeCacheNode):
            # this would mean we couldn't tell where our tree ended and the value
            # started.
            raise ValueError("Cannot store TreeCacheNodes in a TreeCache")

        node = self.root
        for k in key[:-1]:
            next_node = node.get(k, SENTINEL)
            if next_node is SENTINEL:
                next_node = node[k] = TreeCacheNode()
            elif not isinstance(next_node, TreeCacheNode):
                # this suggests that the caller is not being consistent with its key
                # length.
                raise ValueError("value conflicts with an existing subtree")
            node = next_node

        node[key[-1]] = value
        self.size += 1

    def get(self, key, default=None):
        """When `key` is a full key, fetches the value for the given key (if
        any).

        If `key` is only a partial key (i.e. a truncated tuple) then returns a
        `TreeCacheNode`, which can be passed to the `iterate_tree_cache_*`
        functions to iterate over all entries in the cache with keys that start
        with the given partial key.
        """

        node = self.root
        for k in key[:-1]:
            node = node.get(k, None)
            if node is None:
                return default
        return node.get(key[-1], default)

    def clear(self) -> None:
        self.size = 0
        self.root = TreeCacheNode()

    def pop(self, key, default=None):
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
        nodes = []

        node = self.root
        for k in key[:-1]:
            node = node.get(k, None)
            if node is None:
                return default
            if not isinstance(node, TreeCacheNode):
                # we've gone off the end of the tree
                raise ValueError("pop() key too long")
            nodes.append(node)  # don't add the root node
        popped = node.pop(key[-1], SENTINEL)
        if popped is SENTINEL:
            return default

        # working back up the tree, clear out any nodes that are now empty
        node_and_keys = list(zip(nodes, key))
        node_and_keys.reverse()
        node_and_keys.append((self.root, None))

        for i in range(len(node_and_keys) - 1):
            n, k = node_and_keys[i]

            if n:
                break
            # found an empty node: remove it from its parent, and loop.
            node_and_keys[i + 1][0].pop(k)

        cnt = sum(1 for _ in iterate_tree_cache_entry(popped))
        self.size -= cnt
        return popped

    def values(self):
        return iterate_tree_cache_entry(self.root)

    def items(self):
        return iterate_tree_cache_items((), self.root)

    def __len__(self) -> int:
        return self.size


def iterate_tree_cache_entry(d):
    """Helper function to iterate over the leaves of a tree, i.e. a dict of that
    can contain dicts.
    """
    if isinstance(d, TreeCacheNode):
        for value_d in d.values():
            yield from iterate_tree_cache_entry(value_d)
    else:
        yield d


def iterate_tree_cache_items(key, value):
    """Helper function to iterate over the leaves of a tree, i.e. a dict of that
    can contain dicts.

    The provided key is a tuple that will get prepended to the returned keys.

    Example:

        cache = TreeCache()
        cache[(1, 1)] = "a"
        cache[(1, 2)] = "b"
        cache[(2, 1)] = "c"

        tree_node = cache.get((1,))

        items = iterate_tree_cache_items((1,), tree_node)
        assert list(items) == [((1, 1), "a"), ((1, 2), "b")]

    Returns:
        A generator yielding key/value pairs.
    """
    if isinstance(value, TreeCacheNode):
        for sub_key, sub_value in value.items():
            yield from iterate_tree_cache_items((*key, sub_key), sub_value)
    else:
        # we've reached a leaf of the tree.
        yield key, value
