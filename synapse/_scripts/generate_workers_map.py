#!/usr/bin/env python
# Copyright 2022 The Matrix.org Foundation C.I.C.
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
import itertools
import logging

import yaml

from synapse.config.homeserver import HomeServerConfig
from synapse.rest import ClientRestResource
from synapse.server import HomeServer
from synapse.storage import DataStore

logger = logging.getLogger("generate_workers_map")


class MockHomeserver(HomeServer):
    DATASTORE_CLASS = DataStore

    def __init__(self, config):
        super().__init__(config.server.server_name, config=config)


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Updates a synapse database to the latest schema and optionally runs background updates"
            " on it."
        )
    )
    parser.add_argument("-v", action="store_true")
    parser.add_argument(
        "--config-path",
        type=argparse.FileType("r"),
        required=True,
        help="Synapse configuration file",
    )

    args = parser.parse_args()

    logging_config = {
        "level": logging.DEBUG if args.v else logging.INFO,
        "format": "%(asctime)s - %(name)s - %(lineno)d - %(levelname)s - %(message)s",
    }
    # TODO
    #logging.basicConfig(**logging_config)

    # Load, process and sanity-check the config.
    hs_config = yaml.safe_load(args.config_path)

    config = HomeServerConfig()
    config.parse_config_dict(hs_config, "", "")

    hs = MockHomeserver(config)

    # Setup instantiates the store within the homeserver object and updates the
    # DB.
    #
    # TODO This doesn't really need to access the database.
    hs.setup()

    client_resource = ClientRestResource(hs)

    for path_entry in itertools.chain(*client_resource.path_regexs.values()):
        # This assumes the servlet is attached to a class.
        if getattr(path_entry.callback.__self__, "WORKERS", False):
            print(path_entry.pattern.pattern)


if __name__ == "__main__":
    main()
