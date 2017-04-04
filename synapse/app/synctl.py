#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright 2014-2016 OpenMarket Ltd
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
import collections
import glob
import os
import os.path
import signal
import subprocess
import sys
import yaml
import errno
import time

SYNAPSE = [sys.executable, "-B", "-m", "synapse.app.homeserver"]

GREEN = "\x1b[1;32m"
YELLOW = "\x1b[1;33m"
RED = "\x1b[1;31m"
NORMAL = "\x1b[m"


def pid_running(pid):
    try:
        os.kill(pid, 0)
        return True
    except OSError, err:
        if err.errno == errno.EPERM:
            return True
        return False


def write(message, colour=NORMAL, stream=sys.stdout):
    if colour == NORMAL:
        stream.write(message + "\n")
    else:
        stream.write(colour + message + NORMAL + "\n")


def abort(message, colour=RED, stream=sys.stderr):
    write(message, colour, stream)
    sys.exit(1)


def start(configfile):
    write("Starting ...")
    args = SYNAPSE
    args.extend(["--daemonize", "-c", configfile])

    try:
        subprocess.check_call(args)
        write("started synapse.app.homeserver(%r)" %
              (configfile,), colour=GREEN)
    except subprocess.CalledProcessError as e:
        write(
            "error starting (exit code: %d); see above for logs" % e.returncode,
            colour=RED,
        )


def start_worker(app, configfile, worker_configfile):
    args = [
        "python", "-B",
        "-m", app,
        "-c", configfile,
        "-c", worker_configfile
    ]

    try:
        subprocess.check_call(args)
        write("started %s(%r)" % (app, worker_configfile), colour=GREEN)
    except subprocess.CalledProcessError as e:
        write(
            "error starting %s(%r) (exit code: %d); see above for logs" % (
                app, worker_configfile, e.returncode,
            ),
            colour=RED,
        )


def stop(pidfile, app):
    if os.path.exists(pidfile):
        pid = int(open(pidfile).read())
        try:
            os.kill(pid, signal.SIGTERM)
            write("stopped %s" % (app,), colour=GREEN)
        except OSError, err:
            if err.errno == errno.ESRCH:
                write("%s not running" % (app,), colour=YELLOW)
            elif err.errno == errno.EPERM:
                abort("Cannot stop %s: Operation not permitted" % (app,))
            else:
                abort("Cannot stop %s: Unknown error" % (app,))


Worker = collections.namedtuple("Worker", [
    "app", "configfile", "pidfile", "cache_factor"
])


def main():

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "action",
        choices=["start", "stop", "restart"],
        help="whether to start, stop or restart the synapse",
    )
    parser.add_argument(
        "configfile",
        nargs="?",
        default="homeserver.yaml",
        help="the homeserver config file, defaults to homserver.yaml",
    )
    parser.add_argument(
        "-w", "--worker",
        metavar="WORKERCONFIG",
        help="start or stop a single worker",
    )
    parser.add_argument(
        "-a", "--all-processes",
        metavar="WORKERCONFIGDIR",
        help="start or stop all the workers in the given directory"
             " and the main synapse process",
    )

    options = parser.parse_args()

    if options.worker and options.all_processes:
        write(
            'Cannot use "--worker" with "--all-processes"',
            stream=sys.stderr
        )
        sys.exit(1)

    configfile = options.configfile

    if not os.path.exists(configfile):
        write(
            "No config file found\n"
            "To generate a config file, run '%s -c %s --generate-config"
            " --server-name=<server name>'\n" % (
                " ".join(SYNAPSE), options.configfile
            ),
            stream=sys.stderr,
        )
        sys.exit(1)

    with open(configfile) as stream:
        config = yaml.load(stream)

    pidfile = config["pid_file"]
    cache_factor = config.get("synctl_cache_factor")
    start_stop_synapse = True

    if cache_factor:
        os.environ["SYNAPSE_CACHE_FACTOR"] = str(cache_factor)

    worker_configfiles = []
    if options.worker:
        start_stop_synapse = False
        worker_configfile = options.worker
        if not os.path.exists(worker_configfile):
            write(
                "No worker config found at %r" % (worker_configfile,),
                stream=sys.stderr,
            )
            sys.exit(1)
        worker_configfiles.append(worker_configfile)

    if options.all_processes:
        worker_configdir = options.all_processes
        if not os.path.isdir(worker_configdir):
            write(
                "No worker config directory found at %r" % (worker_configdir,),
                stream=sys.stderr,
            )
            sys.exit(1)
        worker_configfiles.extend(sorted(glob.glob(
            os.path.join(worker_configdir, "*.yaml")
        )))

    workers = []
    for worker_configfile in worker_configfiles:
        with open(worker_configfile) as stream:
            worker_config = yaml.load(stream)
        worker_app = worker_config["worker_app"]
        worker_pidfile = worker_config["worker_pid_file"]
        worker_daemonize = worker_config["worker_daemonize"]
        assert worker_daemonize, "In config %r: expected '%s' to be True" % (
            worker_configfile, "worker_daemonize")
        worker_cache_factor = worker_config.get("synctl_cache_factor")
        workers.append(Worker(
            worker_app, worker_configfile, worker_pidfile, worker_cache_factor,
        ))

    action = options.action

    if action == "stop" or action == "restart":
        for worker in workers:
            stop(worker.pidfile, worker.app)

        if start_stop_synapse:
            stop(pidfile, "synapse.app.homeserver")

    # Wait for synapse to actually shutdown before starting it again
    if action == "restart":
        running_pids = []
        if start_stop_synapse and os.path.exists(pidfile):
            running_pids.append(int(open(pidfile).read()))
        for worker in workers:
            if os.path.exists(worker.pidfile):
                running_pids.append(int(open(worker.pidfile).read()))
        if len(running_pids) > 0:
            write("Waiting for process to exit before restarting...")
            for running_pid in running_pids:
                while pid_running(running_pid):
                    time.sleep(0.2)

    if action == "start" or action == "restart":
        if start_stop_synapse:
            start(configfile)

        for worker in workers:
            if worker.cache_factor:
                os.environ["SYNAPSE_CACHE_FACTOR"] = str(worker.cache_factor)

            start_worker(worker.app, configfile, worker.configfile)

            if cache_factor:
                os.environ["SYNAPSE_CACHE_FACTOR"] = str(cache_factor)
            else:
                os.environ.pop("SYNAPSE_CACHE_FACTOR", None)


if __name__ == "__main__":
    main()
