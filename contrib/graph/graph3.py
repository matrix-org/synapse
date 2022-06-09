# Copyright 2016 OpenMarket Ltd
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

import pydot

from synapse.api.room_versions import KNOWN_ROOM_VERSIONS
from synapse.events import make_event_from_dict
from synapse.util.frozenutils import unfreeze


def make_graph(file_name: str, file_prefix: str, limit: int) -> None:
    """
    Generate a dot and SVG file for a graph of events in the room based on the
    topological ordering by reading line-delimited JSON from a file.
    """
    print("Reading lines")
    with open(file_name) as f:
        lines = f.readlines()

    print("Read lines")

    # Figure out the room version, assume the first line is the create event.
    room_version = KNOWN_ROOM_VERSIONS[
        json.loads(lines[0]).get("content", {}).get("room_version")
    ]

    events = [make_event_from_dict(json.loads(line), room_version) for line in lines]

    print("Loaded events.")

    events.sort(key=lambda e: e.depth)

    print("Sorted events")

    if limit:
        events = events[-int(limit) :]

    node_map = {}

    graph = pydot.Dot(graph_name="Test")

    for event in events:
        t = datetime.datetime.fromtimestamp(
            float(event.origin_server_ts) / 1000
        ).strftime("%Y-%m-%d %H:%M:%S,%f")

        content = json.dumps(unfreeze(event.get_dict()["content"]), indent=4)
        content = content.replace("\n", "<br/>\n")

        print(content)
        content = []
        for key, value in unfreeze(event.get_dict()["content"]).items():
            if value is None:
                value = "<null>"
            elif isinstance(value, str):
                pass
            else:
                value = json.dumps(value)

            content.append(
                "<b>%s</b>: %s,"
                % (
                    html.escape(key, quote=True).encode("ascii", "xmlcharrefreplace"),
                    html.escape(value, quote=True).encode("ascii", "xmlcharrefreplace"),
                )
            )

        content = "<br/>\n".join(content)

        print(content)

        label = (
            "<"
            "<b>%(name)s </b><br/>"
            "Type: <b>%(type)s </b><br/>"
            "State key: <b>%(state_key)s </b><br/>"
            "Content: <b>%(content)s </b><br/>"
            "Time: <b>%(time)s </b><br/>"
            "Depth: <b>%(depth)s </b><br/>"
            ">"
        ) % {
            "name": event.event_id,
            "type": event.type,
            "state_key": event.get("state_key", None),
            "content": content,
            "time": t,
            "depth": event.depth,
        }

        node = pydot.Node(name=event.event_id, label=label)

        node_map[event.event_id] = node
        graph.add_node(node)

    print("Created Nodes")

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

    print("Created edges")

    graph.write("%s.dot" % file_prefix, format="raw", prog="dot")

    print("Created Dot")

    graph.write_svg("%s.svg" % file_prefix, prog="dot")

    print("Created svg")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Generate a PDU graph for a given room by reading "
        "from a file with line deliminated events. \n"
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
    parser.add_argument("event_file")

    args = parser.parse_args()

    make_graph(args.event_file, args.prefix, args.limit)
