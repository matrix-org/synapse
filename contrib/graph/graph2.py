# Copyright 2014-2016 OpenMarket Ltd
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


import sqlite3
import pydot
import cgi
import json
import datetime
import argparse

from synapse.events import FrozenEvent
from synapse.util.frozenutils import unfreeze


def make_graph(db_name, room_id, file_prefix, limit):
    conn = sqlite3.connect(db_name)

    sql = (
        "SELECT json FROM event_json as j "
        "INNER JOIN events as e ON e.event_id = j.event_id "
        "WHERE j.room_id = ?"
    )

    args = [room_id]

    if limit:
        sql += (
            " ORDER BY topological_ordering DESC, stream_ordering DESC "
            "LIMIT ?"
        )

        args.append(limit)

    c = conn.execute(sql, args)

    events = [FrozenEvent(json.loads(e[0])) for e in c.fetchall()]

    events.sort(key=lambda e: e.depth)

    node_map = {}
    state_groups = {}

    graph = pydot.Dot(graph_name="Test")

    for event in events:
        c = conn.execute(
            "SELECT state_group FROM event_to_state_groups "
            "WHERE event_id = ?",
            (event.event_id,)
        )

        res = c.fetchone()
        state_group = res[0] if res else None

        if state_group is not None:
            state_groups.setdefault(state_group, []).append(event.event_id)

        t = datetime.datetime.fromtimestamp(
            float(event.origin_server_ts) / 1000
        ).strftime('%Y-%m-%d %H:%M:%S,%f')

        content = json.dumps(unfreeze(event.get_dict()["content"]))

        label = (
            "<"
            "<b>%(name)s </b><br/>"
            "Type: <b>%(type)s </b><br/>"
            "State key: <b>%(state_key)s </b><br/>"
            "Content: <b>%(content)s </b><br/>"
            "Time: <b>%(time)s </b><br/>"
            "Depth: <b>%(depth)s </b><br/>"
            "State group: %(state_group)s<br/>"
            ">"
        ) % {
            "name": event.event_id,
            "type": event.type,
            "state_key": event.get("state_key", None),
            "content": cgi.escape(content, quote=True),
            "time": t,
            "depth": event.depth,
            "state_group": state_group,
        }

        node = pydot.Node(
            name=event.event_id,
            label=label,
        )

        node_map[event.event_id] = node
        graph.add_node(node)

    for event in events:
        for prev_id, _ in event.prev_events:
            try:
                end_node = node_map[prev_id]
            except:
                end_node = pydot.Node(
                    name=prev_id,
                    label="<<b>%s</b>>" % (prev_id,),
                )

                node_map[prev_id] = end_node
                graph.add_node(end_node)

            edge = pydot.Edge(node_map[event.event_id], end_node)
            graph.add_edge(edge)

    for group, event_ids in state_groups.items():
        if len(event_ids) <= 1:
            continue

        cluster = pydot.Cluster(
            str(group),
            label="<State Group: %s>" % (str(group),)
        )

        for event_id in event_ids:
            cluster.add_node(node_map[event_id])

        graph.add_subgraph(cluster)

    graph.write('%s.dot' % file_prefix, format='raw', prog='dot')
    graph.write_svg("%s.svg" % file_prefix, prog='dot')

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Generate a PDU graph for a given room by talking "
                    "to the given homeserver to get the list of PDUs. \n"
                    "Requires pydot."
    )
    parser.add_argument(
        "-p", "--prefix", dest="prefix",
        help="String to prefix output files with",
        default="graph_output"
    )
    parser.add_argument(
        "-l", "--limit",
        help="Only retrieve the last N events.",
    )
    parser.add_argument('db')
    parser.add_argument('room')

    args = parser.parse_args()

    make_graph(args.db, args.room, args.prefix, args.limit)
