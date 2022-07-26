#! /usr/bin/env python
import argparse
import logging
import sys
from collections import defaultdict, Counter
from graphlib import TopologicalSorter
from pprint import pformat
from typing import Mapping, Sequence, Dict, List, Tuple, Iterable, Collection
from unittest.mock import MagicMock, patch

import dictdiffer
import pydot
import yaml

from twisted.internet import task

from synapse.config._base import RootConfig
from synapse.config.cache import CacheConfig
from synapse.config.database import DatabaseConfig
from synapse.config.homeserver import HomeServerConfig
from synapse.config.workers import WorkerConfig
from synapse.events import EventBase
from synapse.server import HomeServer
from synapse.state import StateResolutionStore
from synapse.storage.databases.main.event_federation import EventFederationWorkerStore
from synapse.storage.databases.main.events_worker import EventsWorkerStore
from synapse.storage.databases.main.room import RoomWorkerStore
from synapse.storage.databases.main.state import StateGroupWorkerStore
from synapse.types import ISynapseReactor, StateMap, MutableStateMap

logger = logging.getLogger(sys.argv[0])


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

    def __init__(self, config: HomeServerConfig):
        super(MockHomeserver, self).__init__(
            hostname="stateres-debug",
            config=config,
        )


def node(event: EventBase, **kwargs) -> pydot.Node:
    kwargs.setdefault(
        "label",
        f"{event.event_id}\n{event.type}",
    )
    type_to_shape = {"m.room.member": "oval"}
    if "shape" not in kwargs and event.type in type_to_shape:
        kwargs["shape"] = type_to_shape[event.type]

    q = pydot.quote_if_necessary
    return pydot.Node(q(event.event_id), **kwargs)


def edge(source: EventBase, target: EventBase, **kwargs) -> pydot.Edge:
    return pydot.Edge(
        pydot.quote_if_necessary(source.event_id),
        pydot.quote_if_necessary(target.event_id),
        **kwargs,
    )


async def dump_auth_chains(
    hs: MockHomeserver, state_after_parents: Mapping[str, StateMap[str]]
):
    graph = pydot.Dot(rankdir="BT")
    graph.set_node_defaults(shape="box", style="filled")
    q = pydot.quote_if_necessary

    # Key: event id
    # Value: bitmaps. ith bit is set iff this belongs to the auth chain of the ith
    # starting event.
    seen: Dict[str, int] = defaultdict(int)
    edges = set()

    for i, start in enumerate(state_after_parents):
        bitmask = 1 << i
        # DFS starting at `start`. Entries are (event, auth event index).
        stack: List[Tuple[str, int]] = [(start, 0)]
        while stack:
            # Fetch the event we're considering and our progress through its auth events.
            eid, pindex = stack[-1]
            event = await hs.get_datastores().main.get_event(eid, allow_none=True)
            assert event is not None

            # If we've already considered all of its auth events, we can mark this one
            # As having been seen by `start`.
            if pindex >= len(event.auth_event_ids()):
                seen[eid] |= bitmask
                stack.pop()
                continue

            pid = event.auth_event_ids()[pindex]
            edges.add((eid, pid))
            # If we've already marked that `start` can see `pid`, try the next auth event
            if seen.get(pid, 0) & bitmask:
                stack[-1] = (eid, pindex + 1)
                continue

            # Otherwise, continue DFS at pid
            stack.append((pid, 0))

    for eid, bitmask in seen.items():
        event = await hs.get_datastores().main.get_event(eid, allow_none=True)
        assert event is not None
        colors = ["gray", "orangered", "lightskyblue", "mediumorchid1"]
        graph.add_node(node(event, fillcolor=colors[bitmask]))
    for eid, pid in edges:
        graph.add_edge(pydot.Edge(q(eid), q(pid)))

    graph.write_raw("auth_chains.dot")
    graph.write_svg("auth_chains.svg")


async def dump_mainlines(
    hs: MockHomeserver,
    starting_event: EventBase,
    extras: Collection[EventBase] = tuple(),
):
    graph = pydot.Dot(rankdir="BT")
    graph.set_node_defaults(shape="box", style="filled")

    graph.add_node(node(starting_event, fillcolor="#6699cc"))
    seen = {starting_event.event_id}

    todo = []
    for extra in extras:
        graph.add_node(node(extra, fillcolor="#cc9966"))
        seen.add(extra.event_id)
        todo.append(extra)

    for pid in starting_event.prev_event_ids():
        parent = await hs.get_datastores().main.get_event(pid)
        graph.add_node(node(parent, fillcolor="#6699cc"))
        seen.add(pid)
        graph.add_edge(edge(starting_event, parent, style="dashed"))
        todo.append(parent)

    while todo:
        event = todo.pop()
        auth_events = {
            (e.type, e.state_key): e
            for e in (
                await hs.get_datastores().main.get_events(event.auth_event_ids())
            ).values()
        }

        for key, style in [
            (("m.room.power_levels", ""), "dashed"),
            (("m.room.join_rules", ""), "dashed"),
            (("m.room.member", event.sender), "dotted"),
        ]:
            auth_event = auth_events.get(key)
            if auth_event:
                if auth_event.event_id not in seen:
                    if key[0] == "m.room.power_levels":
                        graph.add_node(node(auth_event, fillcolor="#ffcccc"))
                    else:
                        graph.add_node(node(auth_event))
                    seen.add(auth_event.event_id)
                    todo.append(auth_event)
                graph.add_edge(edge(event, auth_event))

    graph.write_raw("mainlines.dot")
    graph.write_svg("mainlines.svg")


parser = argparse.ArgumentParser(
    description="Explain the calculation which resolves state prior before an event"
)
parser.add_argument(
    "config_file", help="Synapse config file", type=argparse.FileType("r")
)
parser.add_argument("--verbose", "-v", help="Log verbosely", action="store_true")
parser.add_argument(
    "--debug", "-d", help="Enter debugger after state is resolved", action="store_true"
)
subparsers = parser.add_subparsers()


async def debug_specific_stateres(
    reactor: ISynapseReactor, hs: MockHomeserver, args: argparse.Namespace
) -> None:
    # Fetch the event in question.
    event = await hs.get_datastores().main.get_event(args.event_id)
    assert event is not None
    logger.info("event %s has %d parents, %s", event.event_id, len(event.prev_event_ids()), event.prev_event_ids())

    state_after_parents = [
        await hs.get_storage_controllers().state.get_state_ids_for_event(prev_event_id)
        for prev_event_id in event.prev_event_ids()
    ]

    # await dump_auth_chains(hs, state_after_parents)
    extras = await hs.get_datastores().main.get_events(
        [
            "$SIRWGpXP-CV6XtCdeHgFY_PIJXUzOHkaCUMsRN6RFes",
            "$LgVDro6FUgz-qQJhGgeLGmvgc9xFZRJlyiHuia_VH78",
        ]
    )
    await dump_mainlines(hs, event, extras.values())

    result = await hs.get_state_resolution_handler().resolve_events_with_store(
        event.room_id,
        event.room_version.identifier,
        state_after_parents,
        event_map=None,
        state_res_store=StateResolutionStore(hs.get_datastores().main),
    )

    logger.info("State resolved at %s:", event.event_id)
    logger.info(pformat(result))

    logger.info("Stored state at %s:", event.event_id)
    stored_state = await hs.get_storage_controllers().state.get_state_ids_for_event(
        event.event_id
    )
    logger.info(pformat(stored_state))

    logger.info("Diff from stored to resolved:")
    for change in dictdiffer.diff(stored_state, result):
        logger.info(pformat(change))

    if args.debug:
        print(
            f"see state_after_parents[i] for i in range({len(state_after_parents)})"
            " and result",
            file=sys.stderr,
        )
        breakpoint()


debug_parser = subparsers.add_parser(
    "debug",
    description="debug the stateres calculation of a specific event",
)
debug_parser.add_argument("event_id", help="the event ID to be resolved")
debug_parser.set_defaults(func=debug_specific_stateres)


async def debug_specific_room(
    reactor: ISynapseReactor, hs: MockHomeserver, args: argparse.Namespace
) -> None:
    main = hs.get_datastores().main
    event_ids = await main.db_pool.simple_select_onecol(
        "events",
        {"room_id": args.room_id},
        "event_id",
    )

    starting_points: Sequence[str] = await main.db_pool.simple_select_onecol(
        "event_backward_extremities",
        {"room_id": args.room_id},
        "event_id",
    )
    if not starting_points:
        starting_points = [
            await main.db_pool.simple_select_one_onecol(
                "events",
                {"room_id": args.room_id, "type": "m.room.create", "state_key": ""},
                "event_id",
            )
        ]

    logger.info("starting points are %s", starting_points)
    state_after: Dict[str, StateMap[str]] = {
        e: await hs.get_storage_controllers().state.get_state_ids_for_event(e)
        for e in starting_points
    }

    events = await main.get_events(event_ids)
    sorter: TopologicalSorter[str] = TopologicalSorter()
    for event in events.values():
        sorter.add(event.event_id, *event.prev_event_ids())

    frequency_of_state_res_by_size: Dict[int, int] = defaultdict(int)

    for eid in sorter.static_order():
        if eid in state_after:
            logger.debug("Skip %s", eid)
            continue
        logger.debug("Consider %s", eid)

        event = events[eid]
        state_after_parents = [state_after[pid] for pid in event.prev_event_ids()]
        frequency_of_state_res_by_size[len(state_after_parents)] += 1

        # The state before
        state_at = dict(
            await hs.get_state_resolution_handler().resolve_events_with_store(
                event.room_id,
                event.room_version.identifier,
                state_after_parents,
                event_map=None,
                state_res_store=StateResolutionStore(hs.get_datastores().main),
            )
        )

        ## Extra dict above is to keep mypy happy

        state_delta = (
            {(event.type, event.state_key): event.event_id}
            if event.is_state() and event.rejected_reason is None
            else {}
        )
        # The state after
        state_at.update(state_delta)
        state_after[event.event_id] = state_at

        # Retrieve the stored state
        stored_state = await hs.get_storage_controllers().state.get_state_ids_for_event(
            event.event_id
        )
        assert stored_state == state_at
    logger.info(
        "state res sizes -> frequency: %s", pformat(frequency_of_state_res_by_size)
    )


room_parser = subparsers.add_parser(
    "room", description="debug the stateres calculation of an entire room"
)
room_parser.add_argument("room_id", help="the room ID to be interrogated")
room_parser.set_defaults(func=debug_specific_room)


if __name__ == "__main__":
    args = parser.parse_args()
    logging.basicConfig(
        format="%(asctime)s %(name)s:%(lineno)d %(levelname)s %(message)s",
        level=logging.DEBUG if args.verbose else logging.INFO,
        stream=sys.stdout,
    )
    logging.getLogger("synapse.util").setLevel(logging.ERROR)
    logging.getLogger("synapse.storage").setLevel(logging.ERROR)

    config = load_config(args.config_file)
    hs = MockHomeserver(config)
    with patch("synapse.storage.databases.prepare_database"), patch(
        "synapse.storage.database.BackgroundUpdater"
    ), patch("synapse.storage.databases.main.events_worker.MultiWriterIdGenerator"):
        hs.setup()

    task.react(args.func, [hs, parser.parse_args()])
