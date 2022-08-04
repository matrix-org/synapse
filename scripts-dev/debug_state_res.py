#! /usr/bin/env python
import argparse
import logging
import sys
from pprint import pformat
from typing import Awaitable, Callable, Collection, Dict, List, Optional, Tuple, cast
from unittest.mock import MagicMock, patch

import dictdiffer
import pydot
import yaml

from twisted.internet import task

from synapse.config._base import RootConfig
from synapse.config.cache import CacheConfig
from synapse.config.database import DatabaseConfig
from synapse.config.workers import WorkerConfig
from synapse.events import EventBase
from synapse.server import HomeServer
from synapse.state import StateResolutionStore
from synapse.storage.databases.main.event_federation import EventFederationWorkerStore
from synapse.storage.databases.main.events_worker import EventsWorkerStore
from synapse.storage.databases.main.room import RoomWorkerStore
from synapse.storage.databases.main.state import StateGroupWorkerStore
from synapse.storage.state import StateFilter
from synapse.types import ISynapseReactor, StateMap

"""This monstrosity is useful for visualising and debugging state resolution problems.


"""

logger = logging.getLogger(sys.argv[0])


# Bits of the HomeServer Machinery we need to talk to the DB.
class Config(RootConfig):
    config_classes = [DatabaseConfig, WorkerConfig, CacheConfig]


def load_config(source: str) -> Config:
    data = yaml.safe_load(source)
    data["worker_name"] = "stateres-debug"

    config = Config()
    config.parse_config_dict(data, "DUMMYPATH", "DUMMYPATH")
    config.key = MagicMock()  # Don't bother creating signing keys
    return config


class DataStore(
    StateGroupWorkerStore,
    EventFederationWorkerStore,
    EventsWorkerStore,
    RoomWorkerStore,
):
    pass


class MockHomeserver(HomeServer):
    DATASTORE_CLASS = DataStore  # type: ignore [assignment]

    def __init__(self, config: Config):
        super(MockHomeserver, self).__init__(
            hostname="stateres-debug",
            config=config,  # type: ignore[arg-type]
        )


# Functions for drawing graphviz diagrams via `pydot`.
def node(
    event: EventBase, suffix: Optional[str] = None, **kwargs: object
) -> pydot.Node:
    if "label" not in kwargs:
        label = (
            f"{event.event_id}\n{event.sender}: {(event.type,event.get_state_key())}"
        )
        if event.type == "m.room.member":
            label += f" ({event.membership.upper()})"
        if suffix:
            label += f"\n{suffix}"
        kwargs["label"] = label
    type_to_shape: Dict[str, str] = {}  # {"m.room.member": "oval"}
    if event.type in type_to_shape:
        kwargs.setdefault("shape", type_to_shape[event.type])

    q = pydot.quote_if_necessary
    return pydot.Node(q(event.event_id), **kwargs)


def edge(source: EventBase, target: EventBase, **kwargs: object) -> pydot.Edge:
    return pydot.Edge(
        pydot.quote_if_necessary(source.event_id),
        pydot.quote_if_necessary(target.event_id),
        **kwargs,
    )


async def dump_mainlines(
    hs: MockHomeserver,
    resolve_point: Optional[EventBase],
    events: Collection[EventBase],
    extras: Collection[str],
    watch_func: Optional[Callable[[EventBase], Awaitable[str]]] = None,
) -> None:
    """Visualise the auth DAG above a given `starting_event`.

    Starting with the given event's parents and any `extras` of interest, we search in
    their auth events for power levels, join rules and sender membership events.
    We recursively repeat this process for any events found during the search
    until we have no more auth-ancestors of interest to find.

    In this way we build up a subset of the auth chain of the `starting_event`.
    (In particular we omit edges to m.room.create: they are everywhere and convey no
    information.)

    An optional `watch_func` allows us to annotate the events we see with a string of
    our choice. This can be useful if we want to track a single piece of state through
    the auth DAG.
    """
    graph = pydot.Dot(rankdir="BT")
    graph.set_node_defaults(shape="box", style="filled")

    async def new_node(event: EventBase, **kwargs: object) -> pydot.Node:
        suffix = await watch_func(event) if watch_func else None
        return node(event, suffix, **kwargs)

    seen = set()
    todo: List[EventBase] = []

    if resolve_point:
        graph.add_node(await new_node(resolve_point, fillcolor="#6699cc"))
        seen.add(resolve_point.event_id)

    for parent in events:
        graph.add_node(await new_node(parent, fillcolor="#6699cc"))
        seen.add(parent.event_id)
        todo.append(parent)
        if resolve_point:
            graph.add_edge(edge(resolve_point, parent, style="dashed"))

    if extras:
        logger.debug(extras)
        extra_events = await hs.get_datastores().main.get_events(extras)
        logger.debug(extra_events)
        for extra_event in extra_events.values():
            if extra_event.event_id in seen:
                continue
            graph.add_node(await new_node(extra_event, fillcolor="#6699ee"))
            todo.append(extra_event)

    async def fetch_auth_events(event: EventBase) -> StateMap[EventBase]:
        return {
            (e.type, e.state_key): e
            for e in (
                await hs.get_datastores().main.get_events(event.auth_event_ids())
            ).values()
        }

    while todo:
        event = todo.pop()
        auth_events = await fetch_auth_events(event)

        for key, edge_style in [
            (("m.room.power_levels", ""), "solid"),
            (("m.room.join_rules", ""), "solid"),
            (("m.room.member", event.sender), "dotted"),
            # TODO: handle that state_key might be missing
            # (("m.room.member", event.state_key), "solid"),
        ]:
            auth_event = auth_events.get(key)
            if auth_event:
                if auth_event.event_id not in seen:
                    node_options = {}
                    if key[0] == "m.room.power_levels":
                        node_options["fillcolor"] = "#ffcccc"
                    elif key[0] == "m.room.join_rules":
                        node_options["fillcolor"] = "#cc9966"
                    elif key == ("m.room.member", event.sender):
                        auth_events_2 = await fetch_auth_events(auth_event)
                        if ("m.room.member", event.sender) not in auth_events_2:
                            # auth_event is the first join of that sender
                            node_options["fillcolor"] = "#33ff33"
                        else:
                            node_options["fillcolor"] = "#ccffcc"

                    graph.add_node(await new_node(auth_event, **node_options))
                    seen.add(auth_event.event_id)
                    todo.append(auth_event)
                graph.add_edge(edge(event, auth_event, style=edge_style))

    # TODO: make this location configurable
    graph.write_svg("mainlines.svg")


# The main logic and the arguments we need to invoke it.
parser = argparse.ArgumentParser(
    description="Debug the stateres calculation of a specific event."
)
parser.add_argument(
    "config_file", help="Synapse config file", type=argparse.FileType("r")
)
parser.add_argument("--verbose", "-v", help="Log verbosely", action="store_true")
parser.add_argument("-d", "--draw", help="Render auth DAG", action="store_true")
parser.add_argument(
    "event_ids",
    help="""\
The event ID(s) to be resolved.\

If a single event is given, resolve across all of its parents to compute the state
before the given event. If multiple events are given, resolve across them directly.
""",
    nargs="+",
)
parser.add_argument(
    "-e",
    "--extra",
    dest="extras",
    help=(
        "An extra event to include in the auth DAG when using the `--draw` flag. "
        "Can be provided multiple times."
    ),
    action="append",
)
parser.add_argument(
    "--watch",
    help="Track a piece of state in the auth DAG when using the `--draw` flag.",
    default=None,
    nargs=2,
    metavar=("TYPE", "STATE_KEY"),
)


async def debug_specific_stateres(
    reactor: ISynapseReactor, hs: MockHomeserver, args: argparse.Namespace
) -> None:
    """Recompute the state at the given event.

    This produces
    - a file called `mainline.svg` representing the auth chain of the given event,
    - logging from state resolution calculations, written to stdout,
    - the recomputed and stored state, written to stdout, and
    - their difference, written to stdout.
    """
    DEBUG_AT_EVENT = len(args.event_ids) == 1

    if DEBUG_AT_EVENT:
        resolve_point = await hs.get_datastores().main.get_event(args.event_ids[0])
        prev_event_ids = resolve_point.prev_event_ids()
    else:
        resolve_point = None
        prev_event_ids = args.event_ids

    parent_events = (await hs.get_datastores().main.get_events(prev_event_ids)).values()
    sample_event = next(iter(parent_events))

    logger.info("Resolving across %d parents, %s", len(prev_event_ids), prev_event_ids)
    state_after_parents = [
        await hs.get_storage_controllers().state.get_state_ids_for_event(prev_event_id)
        for prev_event_id in prev_event_ids
    ]

    if args.watch is not None:
        key_pair = cast(Tuple[str, str], tuple(args.watch))
        filter = StateFilter.from_types([key_pair])

        watch_func: Optional[Callable[[EventBase], Awaitable[str]]]

        async def watch_func(event: EventBase) -> str:
            try:
                result = (
                    await hs.get_storage_controllers().state.get_state_ids_for_event(
                        event.event_id, filter
                    )
                )
            except RuntimeError:
                return f"\n{key_pair}: <Event unavailable :(>"
            else:
                return f"\n{key_pair}: {result.get(key_pair, '<No event in state>')}"

    else:
        watch_func = None

    if args.draw:
        await dump_mainlines(hs, resolve_point, parent_events, args.extras, watch_func)

    result = await hs.get_state_resolution_handler().resolve_events_with_store(
        sample_event.room_id,
        sample_event.room_version.identifier,
        state_after_parents,
        event_map=None,
        state_res_store=StateResolutionStore(hs.get_datastores().main),
    )

    logger.info("State resolved:")
    logger.info(pformat(result))

    if DEBUG_AT_EVENT:
        logger.info("Stored state at %s:", sample_event.event_id)
        stored_state = await hs.get_storage_controllers().state.get_state_ids_for_event(
            sample_event.event_id
        )
        logger.info(pformat(stored_state))

        # TODO make this a like-for-like comparison.
        logger.info("Diff from stored (after event) to resolved (before event):")
        for change in dictdiffer.diff(stored_state, result):
            logger.info(pformat(change))


# Entrypoint.
if __name__ == "__main__":
    args = parser.parse_args()
    logging.basicConfig(
        format="%(asctime)s %(name)s:%(lineno)d %(levelname)s %(message)s",
        level=logging.DEBUG if args.verbose else logging.INFO,
        stream=sys.stdout,
    )
    # Suppress logs we aren't interested in.
    logging.getLogger("synapse.util").setLevel(logging.ERROR)
    logging.getLogger("synapse.storage").setLevel(logging.ERROR)

    config = load_config(args.config_file)
    hs = MockHomeserver(config)
    # Patch out enough stuff so we can work with a readonly DB connection.
    with patch("synapse.storage.databases.prepare_database"), patch(
        "synapse.storage.database.BackgroundUpdater"
    ), patch("synapse.storage.databases.main.events_worker.MultiWriterIdGenerator"):
        hs.setup()

    task.react(debug_specific_stateres, [hs, parser.parse_args()])
