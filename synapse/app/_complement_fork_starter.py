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
import importlib
import itertools
import multiprocessing
import sys

# This script is intended for test purposes only (within Complement).
# It spawns multiple workers, whilst only going through the code loading process
# once.
#
# TODO more docs
#      Each worker is specified as an argument group (each argument group is
#      separated by '--').
#     ........
#
# Usage:
#   python -m synapse.app._complement_fork_starter \
#     synapse.app.homeserver [args..] -- \
#     synapse.app.generic_worker [args..] -- \
#   ...
#     synapse.app.generic_worker [args..]
from typing import Callable, List, Any

from twisted.internet.main import installReactor


class ProxiedReactor:
    """
    Global state is horrible. Use this proxy reactor so we can 'reinstall'
    the reactor by changing the target of the proxy.
    """

    def __init__(self):
        self.___reactor_target = None

    def ___install(self, new_reactor):
        self.___reactor_target = new_reactor

    def __getattr__(self, attr_name: str) -> Any:
        if attr_name == "___install":
            return self.___install
        return getattr(self.___reactor_target, attr_name)


def _worker_entrypoint(func: Callable[[], None], proxy_reactor: ProxiedReactor, args: List[str]) -> None:
    sys.argv = args

    from twisted.internet.epollreactor import EPollReactor
    proxy_reactor.___install(EPollReactor())
    func()


def main() -> None:
    # Split up the arguments into each workers' arguments
    # Strip out any newlines.
    # HACK
    db_config_path = sys.argv[1]
    args = [arg.replace("\n", "") for arg in sys.argv[2:]]
    args_by_worker: List[List[str]] = [
        list(args)
        for cond, args in itertools.groupby(args, lambda ele: ele != "--")
        if cond and args
    ]

    # Prevent Twisted from installing a shared reactor that all the workers will
    # pick up.
    proxy_reactor = ProxiedReactor()
    installReactor(proxy_reactor)

    # Import the entrypoints for all the workers
    worker_functions = []
    for worker_args in args_by_worker:
        worker_module = importlib.import_module(worker_args[0])
        worker_functions.append(worker_module.main)

    # At this point, we've imported all the main entrypoints for all the workers.
    # Now we basically just fork() out to create the workers we need.
    # Because we're using fork(), all the workers get a clone of this launcher's
    # memory space and don't need to repeat the work of loading the code!
    # Instead of using fork() directly, we use the multiprocessing library,
    # which *can* use fork() on Unix platforms.
    # Now we fork our process!

    # TODO Can we do this better?
    # We need to prepare the database first as otherwise all the workers will
    # try to create a schema version table and some will crash out.
    # HACK
    from synapse._scripts import update_synapse_database
    update_proc = multiprocessing.Process(
        target=_worker_entrypoint, args=(update_synapse_database.main, proxy_reactor, ["update_synapse_database", "--database-config", db_config_path, "--run-background-updates"])
    )
    print("===== PREPARING DATABASE =====", file=sys.stderr)
    update_proc.start()
    print("JNG UPROC", file=sys.stderr)
    update_proc.join()
    print("===== PREPARED DATABASE =====", file=sys.stderr)

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
