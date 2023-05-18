#!/usr/bin/env python
# Copyright 2019 The Matrix.org Foundation C.I.C.
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
import logging
from typing import cast

import yaml

from twisted.internet import defer, reactor as reactor_

from synapse.config.homeserver import HomeServerConfig
from synapse.metrics.background_process_metrics import run_as_background_process
from synapse.server import HomeServer
from synapse.storage import DataStore
from synapse.types import ISynapseReactor
from synapse.util import SYNAPSE_VERSION

# Cast safety: Twisted does some naughty magic which replaces the
# twisted.internet.reactor module with a Reactor instance at runtime.
reactor = cast(ISynapseReactor, reactor_)
logger = logging.getLogger("update_database")


class MockHomeserver(HomeServer):
    DATASTORE_CLASS = DataStore  # type: ignore [assignment]

    def __init__(self, config: HomeServerConfig):
        super(MockHomeserver, self).__init__(
            hostname=config.server.server_name,
            config=config,
            reactor=reactor,
            version_string=f"Synapse/{SYNAPSE_VERSION}",
        )


def run_background_updates(hs: HomeServer) -> None:
    main = hs.get_datastores().main
    state = hs.get_datastores().state

    async def run_background_updates() -> None:
        await main.db_pool.updates.run_background_updates(sleep=False)
        if state:
            await state.db_pool.updates.run_background_updates(sleep=False)
        # Stop the reactor to exit the script once every background update is run.
        reactor.stop()

    def run() -> None:
        # Apply all background updates on the database.
        defer.ensureDeferred(
            run_as_background_process("background_updates", run_background_updates)
        )

    reactor.callWhenRunning(run)

    reactor.run()


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Updates a synapse database to the latest schema and optionally runs background updates"
            " on it."
        )
    )
    parser.add_argument("-v", action="store_true")
    parser.add_argument(
        "--database-config",
        type=argparse.FileType("r"),
        required=True,
        help="Synapse configuration file, giving the details of the database to be updated",
    )
    parser.add_argument(
        "--run-background-updates",
        action="store_true",
        required=False,
        help="run background updates after upgrading the database schema",
    )

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.v else logging.INFO,
        format="%(asctime)s - %(name)s - %(lineno)d - %(levelname)s - %(message)s",
    )

    # Load, process and sanity-check the config.
    hs_config = yaml.safe_load(args.database_config)

    config = HomeServerConfig()
    config.parse_config_dict(hs_config, "", "")

    # Instantiate and initialise the homeserver object.
    hs = MockHomeserver(config)

    # Setup instantiates the store within the homeserver object and updates the
    # DB.
    hs.setup()

    if args.run_background_updates:
        run_background_updates(hs)


if __name__ == "__main__":
    main()
