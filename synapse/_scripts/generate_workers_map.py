#!/usr/bin/env python
# Copyright 2022-2023 The Matrix.org Foundation C.I.C.
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
import re
from collections import defaultdict
from dataclasses import dataclass
from typing import Dict, Iterable, Optional, Pattern, Set, Tuple

import yaml

from synapse.config.homeserver import HomeServerConfig
from synapse.federation.transport.server import (
    TransportLayerServer,
    register_servlets as register_federation_servlets,
)
from synapse.http.server import HttpServer, ServletCallback
from synapse.rest import ClientRestResource
from synapse.rest.key.v2 import RemoteKey
from synapse.server import HomeServer
from synapse.storage import DataStore

logger = logging.getLogger("generate_workers_map")


class MockHomeserver(HomeServer):
    DATASTORE_CLASS = DataStore  # type: ignore

    def __init__(self, config: HomeServerConfig, worker_app: Optional[str]) -> None:
        super().__init__(config.server.server_name, config=config)
        self.config.worker.worker_app = worker_app


GROUP_PATTERN = re.compile(r"\(\?P<[^>]+?>(.+?)\)")


@dataclass
class EndpointDescription:
    """
    Describes an endpoint and how it should be routed.
    """

    # The servlet class that handles this endpoint
    servlet_class: object

    # The category of this endpoint. Is read from the `CATEGORY` constant in the servlet
    # class.
    category: Optional[str]

    # TODO:
    #  - does it need to be routed based on a stream writer config?
    #  - does it benefit from any optimised, but optional, routing?
    #  - what 'opinionated synapse worker class' (event_creator, synchrotron, etc) does
    #    it go in?


class EnumerationResource(HttpServer):
    """
    Accepts servlet registrations for the purposes of building up a description of
    all endpoints.
    """

    def __init__(self, is_worker: bool) -> None:
        self.registrations: Dict[Tuple[str, str], EndpointDescription] = {}
        self._is_worker = is_worker

    def register_paths(
        self,
        method: str,
        path_patterns: Iterable[Pattern],
        callback: ServletCallback,
        servlet_classname: str,
    ) -> None:
        # federation servlet callbacks are wrapped, so unwrap them.
        callback = getattr(callback, "__wrapped__", callback)

        # fish out the servlet class
        servlet_class = callback.__self__.__class__  # type: ignore

        if self._is_worker and method in getattr(
            servlet_class, "WORKERS_DENIED_METHODS", ()
        ):
            # This endpoint would cause an error if called on a worker, so pretend it
            # was never registered!
            return

        sd = EndpointDescription(
            servlet_class=servlet_class,
            category=getattr(servlet_class, "CATEGORY", None),
        )

        for pat in path_patterns:
            self.registrations[(method, pat.pattern)] = sd


def get_registered_paths_for_hs(
    hs: HomeServer,
) -> Dict[Tuple[str, str], EndpointDescription]:
    """
    Given a homeserver, get all registered endpoints and their descriptions.
    """

    enumerator = EnumerationResource(is_worker=hs.config.worker.worker_app is not None)
    ClientRestResource.register_servlets(enumerator, hs)
    federation_server = TransportLayerServer(hs)

    # we can't use `federation_server.register_servlets` but this line does the
    # same thing, only it uses this enumerator
    register_federation_servlets(
        federation_server.hs,
        resource=enumerator,
        ratelimiter=federation_server.ratelimiter,
        authenticator=federation_server.authenticator,
        servlet_groups=federation_server.servlet_groups,
    )

    # the key server endpoints are separate again
    RemoteKey(hs).register(enumerator)

    return enumerator.registrations


def get_registered_paths_for_default(
    worker_app: Optional[str], base_config: HomeServerConfig
) -> Dict[Tuple[str, str], EndpointDescription]:
    """
    Given the name of a worker application and a base homeserver configuration,
    returns:

        Dict from (method, path) to EndpointDescription

    TODO Don't require passing in a config
    """

    hs = MockHomeserver(base_config, worker_app)
    # TODO We only do this to avoid an error, but don't need the database etc
    hs.setup()
    return get_registered_paths_for_hs(hs)


def elide_http_methods_if_unconflicting(
    registrations: Dict[Tuple[str, str], EndpointDescription],
    all_possible_registrations: Dict[Tuple[str, str], EndpointDescription],
) -> Dict[Tuple[str, str], EndpointDescription]:
    """
    Elides HTTP methods (by replacing them with `*`) if all possible registered methods
    can be handled by the worker whose registration map is `registrations`.

    i.e. the only endpoints left with methods (other than `*`) should be the ones where
    the worker can't handle all possible methods for that path.
    """

    def paths_to_methods_dict(
        methods_and_paths: Iterable[Tuple[str, str]]
    ) -> Dict[str, Set[str]]:
        """
        Given (method, path) pairs, produces a dict from path to set of methods
        available at that path.
        """
        result: Dict[str, Set[str]] = {}
        for method, path in methods_and_paths:
            result.setdefault(path, set()).add(method)
        return result

    all_possible_reg_methods = paths_to_methods_dict(all_possible_registrations)
    reg_methods = paths_to_methods_dict(registrations)

    output = {}

    for path, handleable_methods in reg_methods.items():
        if handleable_methods == all_possible_reg_methods[path]:
            any_method = next(iter(handleable_methods))
            # TODO This assumes that all methods have the same servlet.
            #      I suppose that's possibly dubious?
            output[("*", path)] = registrations[(any_method, path)]
        else:
            for method in handleable_methods:
                output[(method, path)] = registrations[(method, path)]

    return output


def simplify_path_regexes(
    registrations: Dict[Tuple[str, str], EndpointDescription]
) -> Dict[Tuple[str, str], EndpointDescription]:
    """
    Simplify all the path regexes for the dict of endpoint descriptions,
    so that we don't use the Python-specific regex extensions
    (and also to remove needlessly specific detail).
    """

    def simplify_path_regex(path: str) -> str:
        """
        Given a regex pattern, replaces all named capturing groups (e.g. `(?P<blah>xyz)`)
        with a simpler version available in more common regex dialects (e.g. `.*`).
        """

        # TODO it's hard to choose between these two;
        #      `.*` is a vague simplification
        # return GROUP_PATTERN.sub(r"\1", path)
        return GROUP_PATTERN.sub(r".*", path)

    return {(m, simplify_path_regex(p)): v for (m, p), v in registrations.items()}


def main() -> None:
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

    # TODO
    # logging.basicConfig(**logging_config)

    # Load, process and sanity-check the config.
    hs_config = yaml.safe_load(args.config_path)

    config = HomeServerConfig()
    config.parse_config_dict(hs_config, "", "")

    master_paths = get_registered_paths_for_default(None, config)
    worker_paths = get_registered_paths_for_default(
        "synapse.app.generic_worker", config
    )

    all_paths = {**master_paths, **worker_paths}

    elided_worker_paths = elide_http_methods_if_unconflicting(worker_paths, all_paths)
    elide_http_methods_if_unconflicting(master_paths, all_paths)

    # TODO SSO endpoints (pick_idp etc) NOT REGISTERED BY THIS SCRIPT

    categories_to_methods_and_paths: Dict[
        Optional[str], Dict[Tuple[str, str], EndpointDescription]
    ] = defaultdict(dict)

    for (method, path), desc in elided_worker_paths.items():
        categories_to_methods_and_paths[desc.category][method, path] = desc

    for category, contents in categories_to_methods_and_paths.items():
        print_category(category, contents)


def print_category(
    category_name: Optional[str],
    elided_worker_paths: Dict[Tuple[str, str], EndpointDescription],
) -> None:
    """
    Prints out a category, in documentation page style.

    Example:
    ```
    # Category name
    /path/xyz

    GET /path/abc
    ```
    """

    if category_name:
        print(f"# {category_name}")
    else:
        print("# (Uncategorised requests)")

    for ln in sorted(
        p for m, p in simplify_path_regexes(elided_worker_paths) if m == "*"
    ):
        print(ln)
    print()
    for ln in sorted(
        f"{m:6} {p}" for m, p in simplify_path_regexes(elided_worker_paths) if m != "*"
    ):
        print(ln)
    print()


if __name__ == "__main__":
    main()
