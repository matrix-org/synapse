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
import re
from typing import Pattern

import yaml

from synapse.config.homeserver import HomeServerConfig
from synapse.federation.transport.server import TransportLayerServer
from synapse.rest import ClientRestResource
from synapse.server import HomeServer
from synapse.storage import DataStore

logger = logging.getLogger("generate_workers_map")


class MockHomeserver(HomeServer):
    DATASTORE_CLASS = DataStore

    def __init__(self, config):
        super().__init__(config.server.server_name, config=config)


GROUP_PATTERN = re.compile(r"\(\?P<[^>]+?>(.+?)\)")


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
    # logging.basicConfig(**logging_config)

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
    federation_server = TransportLayerServer(hs)

    # The resulting paths that workers can handle.
    results = []

    # Avoid re-processing servlets (as they might have multiple paths registered separately).
    servlet_names = set()
    for path_entry in itertools.chain(*client_resource.path_regexs.values()):
        if path_entry.servlet_classname in servlet_names:
            continue
        servlet_names.add(path_entry.servlet_classname)

        # This assumes the servlet is attached to a class.
        worker_patterns = getattr(path_entry.callback.__self__, "WORKER_PATTERNS", [])
        for worker_pattern in worker_patterns:
            # Remove any capturing groups and replace with wildcards.
            pattern = GROUP_PATTERN.sub(".*", worker_pattern.pattern)
            results.append(pattern)

    # Federation resources follow slightly different rules.
    for path_entry in itertools.chain(*federation_server.path_regexs.values()):
        if path_entry.servlet_classname in servlet_names:
            continue
        servlet_names.add(path_entry.servlet_classname)

        # This assumes the servlet is attached to a class.
        servlet = path_entry.callback.__wrapped__.__self__
        worker_path = getattr(servlet, "WORKER_PATH", None)
        if worker_path:
            # See synapse.federation.transport.server._base.BaseFederationServlet.register.
            pattern = "^" + servlet.PREFIX + worker_path
            results.append(pattern)

    # Print the results after sorting (to give a stable output).
    for result in sorted(results):
        print(result)


if __name__ == "__main__":
    main()
