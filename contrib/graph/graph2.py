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


import argparse
import datetime
import html
import json
import sqlite3

import pydot

from synapse.api.room_versions import KNOWN_ROOM_VERSIONS
from synapse.events import make_event_from_dict
from synapse.util.frozenutils import unfreeze


def make_graph(db_name: str, room_id: str, file_prefix: str, limit: int) -> None:
    """
    Generate a dot and SVG file for a graph of events in the room based on the
    topological ordering by reading from a Synapse SQLite database.
    """
    conn = sqlite3.connect(db_name)

    sql = "SELECT room_version FROM rooms WHERE room_id = ?"
    c = conn.execute(sql, (room_id,))
    room_version = KNOWN_ROOM_VERSIONS[c.fetchone()[0]]

    sql = (
        "SELECT json, internal_metadata FROM event_json as j "
        "INNER JOIN events as e ON e.event_id = j.event_id "
        "WHERE j.room_id = ?"
    )

    args = [room_id]

    if limit:
        sql += " ORDER BY topological_ordering DESC, stream_ordering DESC LIMIT ?"

        args.append(limit)

    c = conn.execute(sql, args)

    events = [
        make_event_from_dict(json.loads(e[0]), room_version, json.loads(e[1]))
        for e in c.fetchall()
    ]

    events.sort(key=lambda e: e.depth)

    node_map = {}
    state_groups = {}

    graph = pydot.Dot(graph_name="Test")

    for event in events:
        c = conn.execute(
            "SELECT state_group FROM event_to_state_groups WHERE event_id = ?",
            (event.event_id,),
        )

        res = c.fetchone()
        state_group = res[0] if res else None

        if state_group is not None:
            state_groups.setdefault(state_group, []).append(event.event_id)

        t = datetime.datetime.fromtimestamp(
            float(event.origin_server_ts) / 1000
        ).strftime("%Y-%m-%d %H:%M:%S,%f")

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
            "content": html.escape(content, quote=True),
            "time": t,
            "depth": event.depth,
            "state_group": state_group,
        }

        node = pydot.Node(name=event.event_id, label=label)

        node_map[event.event_id] = node
        graph.add_node(node)

    for event in events:
        for prev_id in event.prev_event_ids():
            try:
                end_node = node_map[prev_id]
            except Exception:
                end_node = pydot.Node(name=prev_id, label=f"<<b>{prev_id}</b>>")

                node_map[prev_id] = end_node
                graph.add_node(end_node)

            edge = pydot.Edge(node_map[event.event_id], end_node)
            graph.add_edge(edge)

    for group, event_ids in state_groups.items():
        if len(event_ids) <= 1:
            continue

        cluster = pydot.Cluster(str(group), label=f"<State Group: {str(group)}>")

        for event_id in event_ids:
            cluster.add_node(node_map[event_id])

        graph.add_subgraph(cluster)

    graph.write("%s.dot" % file_prefix, format="raw", prog="dot")
    graph.write_svg("%s.svg" % file_prefix, prog="dot")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Generate a PDU graph for a given room by talking "
        "to the given Synapse SQLite file to get the list of PDUs. \n"
        "Requires pydot."
    )
    parser.add_argument(
        "-p",
        "--prefix",
        dest="prefix",
        help="String to prefix output files with",
        default="graph_output",
    )
    parser.add_argument("-l", "--limit", help="Only retrieve the last N events.")
    parser.add_argument("db")
    parser.add_argument("room")

    args = parser.parse_args()

    make_graph(args.db, args.room, args.prefix, args.limit)
