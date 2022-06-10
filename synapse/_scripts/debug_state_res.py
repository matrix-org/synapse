#! /usr/bin/env python
import argparse
import logging
import sys
from pprint import pformat
from unittest.mock import MagicMock, patch

import dictdiffer
import yaml

from twisted.internet import task

from synapse.config._base import RootConfig
from synapse.config.cache import CacheConfig
from synapse.config.database import DatabaseConfig
from synapse.config.homeserver import HomeServerConfig
from synapse.config.workers import WorkerConfig
from synapse.server import HomeServer
from synapse.state import StateResolutionStore
from synapse.storage.databases.main.event_federation import EventFederationWorkerStore
from synapse.storage.databases.main.events_worker import EventsWorkerStore
from synapse.storage.databases.main.room import RoomWorkerStore
from synapse.storage.databases.main.state import StateGroupWorkerStore
from synapse.types import ISynapseReactor

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


async def main(reactor: ISynapseReactor, args: argparse.Namespace) -> None:
    config = load_config(args.config_file)
    hs = MockHomeserver(config)
    with patch("synapse.storage.databases.prepare_database"), patch(
        "synapse.storage.database.BackgroundUpdater"
    ), patch("synapse.storage.databases.main.events_worker.MultiWriterIdGenerator"):
        hs.setup()

    # Fetch the event in question.
    event = await hs.get_datastores().main.get_event(args.event_id)
    assert event is not None
    logger.info("event %s has %d parents", event.event_id, len(event.prev_event_ids()))

    state_after_parents = []
    for i, prev_event_id in enumerate(event.prev_event_ids()):
        logger.info("parent %d: %s", i, prev_event_id)
        state_after_parents.append(
            await hs.get_storage_controllers().state.get_state_ids_for_event(
                prev_event_id
            )
        )

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

    logger.info("Diff from resolved to stored:")
    for change in dictdiffer.diff(result, stored_state):
        logger.info(change)

    if args.debug:
        print(
            f"see state_after_parents[i] for i in range({len(state_after_parents)}"
            " and result",
            file=sys.stderr,
        )
        breakpoint()


parser = argparse.ArgumentParser(
    description="Explain the calculation which resolves state prior before an event"
)
parser.add_argument("event_id", help="the event ID to be resolved")
parser.add_argument(
    "config_file", help="Synapse config file", type=argparse.FileType("r")
)
parser.add_argument("--verbose", "-v", help="Log verbosely", action="store_true")
parser.add_argument(
    "--debug", "-d", help="Enter debugger after state is resolved", action="store_true"
)


if __name__ == "__main__":
    args = parser.parse_args()
    logging.basicConfig(
        format="%(asctime)s %(name)s:%(lineno)d %(levelname)s %(message)s",
        level=logging.DEBUG if args.verbose else logging.INFO,
        stream=sys.stdout,
    )
    logging.getLogger("synapse.util").setLevel(logging.ERROR)
    logging.getLogger("synapse.storage").setLevel(logging.ERROR)
    task.react(main, [parser.parse_args()])
