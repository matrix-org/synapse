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
from typing import Callable, List


def _worker_entrypoint(func: Callable[[], None], args: List[str]) -> None:
    sys.argv = args
    func()


def main() -> None:
    # Split up the arguments into each workers' arguments
    args_by_worker: List[List[str]] = [
        list(args)
        for cond, args in itertools.groupby(sys.argv[1:], lambda ele: ele != "--")
        if cond
    ]
    print(args_by_worker)
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

    processes = []
    for (func, worker_args) in zip(worker_functions, args_by_worker):
        process = multiprocessing.Process(
            target=_worker_entrypoint, args=(func, worker_args)
        )
        process.start()
        processes.append(process)

    # Be a good parent and wait for our children to die before exiting.
    for process in processes:
        process.join()


if __name__ == "__main__":
    main()
