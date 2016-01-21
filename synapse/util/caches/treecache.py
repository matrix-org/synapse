SENTINEL = object()


class TreeCache(object):
    def __init__(self):
        self.root = {}

    def __setitem__(self, key, value):
        return self.set(key, value)

    def set(self, key, value):
        node = self.root
        for k in key[:-1]:
            node = node.setdefault(k, {})
        node[key[-1]] = value

    def get(self, key, default=None):
        node = self.root
        for k in key[:-1]:
            node = node.get(k, None)
            if node is None:
                return default
        return node.get(key[-1], default)

    def clear(self):
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

        node_and_keys = zip(nodes, key)
        node_and_keys.reverse()
        node_and_keys.append((self.root, None))

        for i in range(len(node_and_keys) - 1):
            n, k = node_and_keys[i]

            if n:
                break
            node_and_keys[i+1][0].pop(k)

        return popped
