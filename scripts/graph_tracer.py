import fileinput
import pydot

nodes = {}
edges = set()

graph = pydot.Dot(graph_name="call_graph", graph_type="digraph")

names = {}
times = {}
deferreds = {}
deferred_edges = set()

root_id = None

for line in fileinput.input():
    try:
        if " calls " in line:
            start, end = line.split(" calls ")
            start, end = start.strip(), end.strip()
            edges.add((start, end))
            print start, end
        if " named " in line:
            node_id, name = line.split(" named ")
            names[node_id.strip()] = name.strip()

            if name.strip() == "Deferred synapse.rest.client.v1.room.RoomSendEventRestServlet.on_PUT":
                root_id = node_id
        if " in " in line:
            node_id, d = line.split(" in ")
            deferreds[node_id.strip()] = d.strip()
        if " time " in line:
            node_id, ms = line.split(" time ")
            times[node_id.strip()] = int(ms.strip())
        if " waits on " in line:
            start, end = line.split(" waits on ")
            start, end = start.strip(), end.strip()
            deferred_edges.add((start, end))
            print start, end
    except Exception as e:
        print "failed %s to parse '%s'" % (e.message, line)


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

print deferred_edges
print root_id

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

for node_id, name in names.items():
    # if times.get(node_id, 100) < 5:
    #     continue

    if node_id in deferreds:
        if not is_in_deferred(deferreds[node_id]):
            continue
    else:
        if not is_in_deferred(node_id):
            continue

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

for parent, child in edges:
    if child not in nodes:
        print child, "not a node"
        continue

    if parent not in nodes:
        print parent, "not a node"
        continue

    edge = pydot.Edge(nodes[parent], nodes[child])
    graph.add_edge(edge)


file_prefix = "call_graph_out"
graph.write('%s.dot' % file_prefix, format='raw', prog='dot')
graph.write_svg("%s.svg" % file_prefix, prog='dot')
