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
#
# ## What this script does
#
# This script spawns multiple workers, whilst only going through the code loading
# process once. The net effect is that start-up time for a swarm of workers is
# reduced, particularly in CPU-constrained environments.
#
# Before the workers are spawned, the database is prepared in order to avoid the
# workers racing.
#
# ## Stability
#
# This script is only intended for use within the Synapse images for the
# Complement test suite.
# There are currently no stability guarantees whatsoever; especially not about:
# - whether it will continue to exist in future versions;
# - the format of its command-line arguments; or
# - any details about its behaviour or principles of operation.
#
# ## Usage
#
# The first argument should be the path to the database configuration, used to
# set up the database. The rest of the arguments are used as follows:
# Each worker is specified as an argument group (each argument group is
# separated by '--').
# The first argument in each argument group is the Python module name of the application
# to start. Further arguments are then passed to that module as-is.
#
# ## Example
#
#   python -m synapse.app.complement_fork_starter path_to_db_config.yaml \
#     synapse.app.homeserver [args..] -- \
#     synapse.app.generic_worker [args..] -- \
#   ...
#     synapse.app.generic_worker [args..]
#
import argparse
import importlib
import itertools
import multiprocessing
import sys
from typing import Any, Callable, List

from twisted.internet.main import installReactor


class ProxiedReactor:
    """
    Twisted tracks the 'installed' reactor as a global variable.
    (Actually, it does some module trickery, but the effect is similar.)

    The default EpollReactor is buggy if it's created before a process is
    forked, then used in the child.
    See https://twistedmatrix.com/trac/ticket/4759#comment:17.

    However, importing certain Twisted modules will automatically create and
    install a reactor if one hasn't already been installed.
    It's not normally possible to re-install a reactor.

    Given the goal of launching workers with fork() to only import the code once,
    this presents a conflict.
    Our work around is to 'install' this ProxiedReactor which prevents Twisted
    from creating and installing one, but which lets us replace the actual reactor
    in use later on.
    """

    def __init__(self) -> None:
        self.___reactor_target: Any = None

    def _install_real_reactor(self, new_reactor: Any) -> None:
        """
        Install a real reactor for this ProxiedReactor to forward lookups onto.

        This method is specific to our ProxiedReactor and should not clash with
        any names used on an actual Twisted reactor.
        """
        self.___reactor_target = new_reactor

    def __getattr__(self, attr_name: str) -> Any:
        return getattr(self.___reactor_target, attr_name)


def _worker_entrypoint(
    func: Callable[[], None], proxy_reactor: ProxiedReactor, args: List[str]
) -> None:
    """
    Entrypoint for a forked worker process.

    We just need to set up the command-line arguments, create our real reactor
    and then kick off the worker's main() function.
    """

    sys.argv = args

    from twisted.internet.epollreactor import EPollReactor

    proxy_reactor._install_real_reactor(EPollReactor())
    func()


def main() -> None:
    """
    Entrypoint for the forking launcher.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("db_config", help="Path to database config file")
    parser.add_argument(
        "args",
        nargs="...",
        help="Argument groups separated by `--`. "
        "The first argument of each group is a Synapse app name. "
        "Subsequent arguments are passed through.",
    )
    ns = parser.parse_args()

    # Split up the subsequent arguments into each workers' arguments;
    # `--` is our delimiter of choice.
    args_by_worker: List[List[str]] = [
        list(args)
        for cond, args in itertools.groupby(ns.args, lambda ele: ele != "--")
        if cond and args
    ]

    # Prevent Twisted from installing a shared reactor that all the workers will
    # inherit when we fork(), by installing our own beforehand.
    proxy_reactor = ProxiedReactor()
    installReactor(proxy_reactor)

    # Import the entrypoints for all the workers.
    worker_functions = []
    for worker_args in args_by_worker:
        worker_module = importlib.import_module(worker_args[0])
        worker_functions.append(worker_module.main)

    # We need to prepare the database first as otherwise all the workers will
    # try to create a schema version table and some will crash out.
    from synapse._scripts import update_synapse_database

    update_proc = multiprocessing.Process(
        target=_worker_entrypoint,
        args=(
            update_synapse_database.main,
            proxy_reactor,
            [
                "update_synapse_database",
                "--database-config",
                ns.db_config,
                "--run-background-updates",
            ],
        ),
    )
    print("===== PREPARING DATABASE =====", file=sys.stderr)
    update_proc.start()
    update_proc.join()
    print("===== PREPARED DATABASE =====", file=sys.stderr)

    # At this point, we've imported all the main entrypoints for all the workers.
    # Now we basically just fork() out to create the workers we need.
    # Because we're using fork(), all the workers get a clone of this launcher's
    # memory space and don't need to repeat the work of loading the code!
    # Instead of using fork() directly, we use the multiprocessing library,
    # which uses fork() on Unix platforms.
    processes = []
    for (func, worker_args) in zip(worker_functions, args_by_worker):
        process = multiprocessing.Process(
            target=_worker_entrypoint, args=(func, proxy_reactor, worker_args)
        )
        process.start()
        processes.append(process)

    # Be a good parent and wait for our children to die before exiting.
    for process in processes:
        process.join()


if __name__ == "__main__":
    main()
