from typing import Dict

SENTINEL = object()


class TreeCache:
    """
    Tree-based backing store for LruCache. Allows subtrees of data to be deleted
    efficiently.
    Keys must be tuples.
    """

    def __init__(self):
        self.size = 0
        self.root = {}  # type: Dict

    def __setitem__(self, key, value):
        return self.set(key, value)

    def __contains__(self, key):
        return self.get(key, SENTINEL) is not SENTINEL

    def set(self, key, value):
        node = self.root
        for k in key[:-1]:
            node = node.setdefault(k, {})
        node[key[-1]] = _Entry(value)
        self.size += 1

    def get(self, key, default=None):
        node = self.root
        for k in key[:-1]:
            node = node.get(k, None)
            if node is None:
                return default
        return node.get(key[-1], _Entry(default)).value

    def clear(self):
        self.size = 0
        self.root = {}

    def pop(self, key, default=None):
        nodes = []

        node = self.root
        for k in key[:-1]:
            node = node.get(k, None)
            nodes.append(node)  # don't add the root node
            if node is None:
                return default
        popped = node.pop(key[-1], SENTINEL)
        if popped is SENTINEL:
            return default

        node_and_keys = list(zip(nodes, key))
        node_and_keys.reverse()
        node_and_keys.append((self.root, None))

        for i in range(len(node_and_keys) - 1):
            n, k = node_and_keys[i]

            if n:
                break
            node_and_keys[i + 1][0].pop(k)

        popped, cnt = _strip_and_count_entires(popped)
        self.size -= cnt
        return popped

    def values(self):
        return list(iterate_tree_cache_entry(self.root))

    def __len__(self):
        return self.size


def iterate_tree_cache_entry(d):
    """Helper function to iterate over the leaves of a tree, i.e. a dict of that
    can contain dicts.
    """
    if isinstance(d, dict):
        for value_d in d.values():
            for value in iterate_tree_cache_entry(value_d):
                yield value
    else:
        if isinstance(d, _Entry):
            yield d.value
        else:
            yield d


class _Entry:
    __slots__ = ["value"]

    def __init__(self, value):
        self.value = value


def _strip_and_count_entires(d):
    """Takes an _Entry or dict with leaves of _Entry's, and either returns the
    value or a dictionary with _Entry's replaced by their values.

    Also returns the count of _Entry's
    """
    if isinstance(d, dict):
        cnt = 0
        for key, value in d.items():
            v, n = _strip_and_count_entires(value)
            d[key] = v
            cnt += n
        return d, cnt
    else:
        return d.value, 1
