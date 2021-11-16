#! /usr/bin/env python3
import argparse
import os
import re
import subprocess
import sys
import tempfile
from typing import Iterable, Optional, Set

import networkx


def scrape_storage_classes() -> str:
    """Grep the for classes ending with "Store" and extract their list of parents.

    Returns the stdout from `rg` as a single string."""

    # TODO: this is a big hack which assumes that each Store class has a unique name.
    #   That assumption is wrong: there are two DirectoryStores, one in
    #   synapse/replication/slave/storage/directory.py and the other in
    #   synapse/storage/databases/main/directory.py
    #   Would be nice to have a way to account for this.

    return subprocess.check_output(
        [
            "rg",
            "-o",
            "--no-line-number",
            "--no-filename",
            "--multiline",
            r"class .*Store\((.|\n)*?\):$",
            "synapse",
            "tests",
        ],
        cwd="/home/dmr/workspace/synapse/",
    ).decode()


oneline_class_pattern = re.compile(r"^class (.*)\((.*)\):$")
opening_class_pattern = re.compile(r"^class (.*)\($")


def load_graph(lines: Iterable[str]) -> networkx.DiGraph:
    """Process the output of scrape_storage_classes to build an inheritance graph.

    Every time a class C is created that explicitly inherits from a parent P, we add an
    edge C -> P.
    """
    G = networkx.DiGraph()
    child: Optional[str] = None

    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if (match := oneline_class_pattern.match(line)) is not None:
            child, parents = match.groups()
            for parent in parents.split(", "):
                if "metaclass" not in parent:
                    G.add_edge(child, parent)

            child = None
        elif (match := opening_class_pattern.match(line)) is not None:
            (child,) = match.groups()
        elif line == "):":
            child = None
        else:
            assert child is not None, repr(line)
            parent = line.strip(",")
            if "metaclass" not in parent:
                G.add_edge(child, parent)

    return G


def select_vertices_of_interest(G: networkx.DiGraph, target: Optional[str]) -> Set[str]:
    """Find all nodes we want to visualise.

    If no TARGET is given, we visualise all of G. Otherwise we visualise a given
    TARGET, its parents, and all of their parents recursively.

    Requires that G is a DAG.
    If not None, the TARGET must belong to G.
    """
    assert networkx.is_directed_acyclic_graph(G)
    if target is not None:
        component: Set[str] = networkx.descendants(G, target)
        component.add(target)
    else:
        component = set(G.nodes)
    return component


def generate_dot_source(G: networkx.DiGraph, nodes: Set[str]) -> str:
    output = """\
strict digraph {
    rankdir="LR";
    node [shape=box];

"""
    for (child, parent) in G.edges:
        if child in nodes and parent in nodes:
            output += f"   {child} -> {parent};\n"
    output += "}\n"
    return output


def render_png(dot_source: str, destination: Optional[str]) -> str:
    if destination is None:
        handle, destination = tempfile.mkstemp()
        os.close(handle)
        print("Warning: writing to", destination, "which will persist", file=sys.stderr)

    subprocess.run(
        [
            "dot",
            "-o",
            destination,
            "-Tpng",
        ],
        input=dot_source,
        encoding="utf-8",
        check=True,
    )
    return destination


def show_graph(location: str) -> None:
    subprocess.run(
        ["xdg-open", location],
        check=True,
    )


def main(parser: argparse.ArgumentParser, args: argparse.Namespace) -> int:
    if not (args.output or args.show):
        parser.print_help(file=sys.stderr)
        print("Must either --output or --show, or both.", file=sys.stderr)
        return os.EX_USAGE

    lines = scrape_storage_classes().split("\n")
    G = load_graph(lines)
    nodes = select_vertices_of_interest(G, args.target)
    dot_source = generate_dot_source(G, nodes)
    output_location = render_png(dot_source, args.output)
    if args.show:
        show_graph(output_location)
    return os.EX_OK


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Visualise the inheritance of Synapse's storage classes. Requires "
        "ripgrep (https://github.com/BurntSushi/ripgrep) as 'rg'; graphviz "
        "(https://graphviz.org/) for the 'dot' program; and networkx "
        "(https://networkx.org/). Requires Python 3.8+ for the walrus"
        "operator."
    )
    parser.add_argument(
        "target",
        nargs="?",
        help="Show only TARGET and its ancestors. Otherwise, show the entire hierarchy.",
    )
    parser.add_argument(
        "--output",
        nargs=1,
        help="Render inheritance graph to a png file.",
    )
    parser.add_argument(
        "--show",
        action="store_true",
        help="Open the inheritance graph in an image viewer.",
    )
    return parser


if __name__ == "__main__":
    parser = build_parser()
    args = parser.parse_args()
    sys.exit(main(parser, args))
