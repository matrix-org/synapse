import argparse
import cgi
import datetime
import json

import pydot
import urllib2

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


def make_name(pdu_id, origin):
    return "%s@%s" % (pdu_id, origin)


def make_graph(pdus, room, filename_prefix):
    pdu_map = {}
    node_map = {}

    origins = set()
    colors = {"red", "green", "blue", "yellow", "purple"}

    for pdu in pdus:
        origins.add(pdu.get("origin"))

    color_map = {color: color for color in colors if color in origins}
    colors -= set(color_map.values())

    color_map[None] = "black"

    for o in origins:
        if o in color_map:
            continue
        try:
            c = colors.pop()
            color_map[o] = c
        except Exception:
            print("Run out of colours!")
            color_map[o] = "black"

    graph = pydot.Dot(graph_name="Test")

    for pdu in pdus:
        name = make_name(pdu.get("pdu_id"), pdu.get("origin"))
        pdu_map[name] = pdu

        t = datetime.datetime.fromtimestamp(float(pdu["ts"]) / 1000).strftime(
            "%Y-%m-%d %H:%M:%S,%f"
        )

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
            "name": name,
            "type": pdu.get("pdu_type"),
            "state_key": pdu.get("state_key"),
            "content": cgi.escape(json.dumps(pdu.get("content")), quote=True),
            "time": t,
            "depth": pdu.get("depth"),
        }

        node = pydot.Node(name=name, label=label, color=color_map[pdu.get("origin")])
        node_map[name] = node
        graph.add_node(node)

    for pdu in pdus:
        start_name = make_name(pdu.get("pdu_id"), pdu.get("origin"))
        for i, o in pdu.get("prev_pdus", []):
            end_name = make_name(i, o)

            if end_name not in node_map:
                print("%s not in nodes" % end_name)
                continue

            edge = pydot.Edge(node_map[start_name], node_map[end_name])
            graph.add_edge(edge)

        # Add prev_state edges, if they exist
        if pdu.get("prev_state_id") and pdu.get("prev_state_origin"):
            prev_state_name = make_name(
                pdu.get("prev_state_id"), pdu.get("prev_state_origin")
            )

            if prev_state_name in node_map:
                state_edge = pydot.Edge(
                    node_map[start_name], node_map[prev_state_name], style="dotted"
                )
                graph.add_edge(state_edge)

    graph.write("%s.dot" % filename_prefix, format="raw", prog="dot")
    #    graph.write_png("%s.png" % filename_prefix, prog='dot')
    graph.write_svg("%s.svg" % filename_prefix, prog="dot")


def get_pdus(host, room):
    transaction = json.loads(
        urllib2.urlopen(
            "http://%s/_matrix/federation/v1/context/%s/" % (host, room)
        ).read()
    )

    return transaction["pdus"]


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Generate a PDU graph for a given room by talking "
        "to the given homeserver to get the list of PDUs. \n"
        "Requires pydot."
    )
    parser.add_argument(
        "-p", "--prefix", dest="prefix", help="String to prefix output files with"
    )
    parser.add_argument("host")
    parser.add_argument("room")

    args = parser.parse_args()

    host = args.host
    room = args.room
    prefix = args.prefix if args.prefix else "%s_graph" % (room)

    pdus = get_pdus(host, room)

    make_graph(pdus, room, prefix)
