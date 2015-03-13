import fileinput
import pydot
import sys
import itertools
import json


def pairwise(iterable):
    "s -> (s0,s1), (s1,s2), (s2, s3), ..."
    a, b = itertools.tee(iterable)
    next(b, None)
    return itertools.izip(a, b)


nodes = {}
edges = set()

graph = pydot.Dot(graph_name="call_graph", graph_type="digraph")

names = {}
starts = {}
ends = {}
deferreds = set()
deferreds_map = {}
deferred_edges = set()

root_id = None

for line in fileinput.input():
    line = line.strip()
    try:
        if " calls " in line:
            start, end = line.split(" calls ")
            start, end = start.strip(), end.strip()
            edges.add((start, end))
            # print start, end
        if " named " in line:
            node_id, name = line.split(" named ")
            names[node_id.strip()] = name.strip()

            if name.strip() == "synapse.rest.client.v1.room.RoomSendEventRestServlet.on_PUT":
                root_id = node_id
        if " in " in line:
            node_id, d = line.split(" in ")
            deferreds_map[node_id.strip()] = d.strip()
        if " is deferred" in line:
            node_id, _ = line.split(" is deferred")
            deferreds.add(node_id)
        if " start " in line:
            node_id, ms = line.split(" start ")
            starts[node_id.strip()] = int(ms.strip())
        if " end " in line:
            node_id, ms = line.split(" end ")
            ends[node_id.strip()] = int(ms.strip())
        if " waits on " in line:
            start, end = line.split(" waits on ")
            start, end = start.strip(), end.strip()
            deferred_edges.add((start, end))
            # print start, end
    except Exception as e:
        sys.stderr.write("failed %s to parse '%s'\n" % (e.message, line))

if not root_id:
    sys.stderr.write("Could not find root")
    sys.exit(1)


# deferreds_root = set(deferreds.values())
# for parent, child in deferred_edges:
#     deferreds_root.discard(child)
#
# deferred_tree = {
#     d: {}
#     for d in deferreds_root
# }
#
# def populate(root, tree):
#     for leaf in deferred_edges.get(root, []):
#         populate(leaf, tree.setdefault(leaf, {}))
#
#
# for d in deferreds_root:
#     tree = deferred_tree.setdefault(d, {})
#     populate(d, tree)

# print deferred_edges
# print root_id

def is_in_deferred(d):
    while True:
        if d == root_id:
            return True

        for start, end in deferred_edges:
            if d == end:
                d = start
                break
        else:
            return False


def walk_graph(d):
    res = [d]
    while d != root_id:
        for start, end in edges:
            if d == end:
                d = start
                res.append(d)
                break
        else:
            return res
    return res


def make_tree_el(node_id):
    return {
        "id": node_id,
        "name": names[node_id],
        "children": [],
        "start": starts[node_id],
        "end": ends[node_id],
        "size": ends[node_id] - starts[node_id],
    }

tree = make_tree_el(root_id)

tree_index = {
    root_id: tree,
}


viz_out = {
    "nodes": [],
    "edges": [],
}

for node_id, name in names.items():
    # if times.get(node_id, 100) < 5:
    #     continue

    walk = walk_graph(node_id)
    # print walk
    if root_id not in walk:
        continue

    if node_id in deferreds:
        if not is_in_deferred(node_id):
            continue
    elif node_id in deferreds_map:
        if not is_in_deferred(deferreds_map[node_id]):
            continue

    walk_names = [
        names[w].split("synapse.", 1)[1] for w in walk
    ]

    for child, parent in reversed(list(pairwise(walk))):
        if parent in tree_index and child not in tree_index:
            el = make_tree_el(child)
            tree_index[parent]["children"].append(el)
            tree_index[child] = el

    # print "-".join(reversed(["end"] + walk_names)) + ", " + str(ends[node_id] - starts[node_id])
    # print "%d,%s,%s,%s" % (len(walk), walk_names[0], starts[node_id], ends[node_id])

    viz_out["nodes"].append({
        "id": node_id,
        "label": names[node_id].split("synapse.", 1)[1],
        "value": ends[node_id] - starts[node_id],
        "level": len(walk),
    })

    node = pydot.Node(node_id, label=name)

    # if node_id in deferreds:
    #     clusters[deferreds[node_id]].add_node(node)
    # elif node_id in clusters:
    #     clusters[node_id].add_node(node)
    # else:
    #     graph.add_node(node)
    graph.add_node(node)
    nodes[node_id] = node

    # print node_id

# for el in tree_index.values():
#     el["children"].sort(key=lambda e: e["start"])
#
# print json.dumps(tree)

for parent, child in edges:
    if child not in nodes:
        # sys.stderr.write(child + " not a node\n")
        continue

    if parent not in nodes:
        # sys.stderr.write(parent + " not a node\n")
        continue

    viz_out["edges"].append({
        "from": parent,
        "to": child,
        "value": ends[child] - starts[child],
    })

    edge = pydot.Edge(nodes[parent], nodes[child])
    graph.add_edge(edge)

print json.dumps(viz_out)

file_prefix = "call_graph_out"
graph.write('%s.dot' % file_prefix, format='raw', prog='dot')
graph.write_svg("%s.svg" % file_prefix, prog='dot')
