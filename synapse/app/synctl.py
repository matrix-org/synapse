#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright 2014, 2015 OpenMarket Ltd
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

import sys
import os
import subprocess
import signal

SYNAPSE = ["python", "-B", "-m", "synapse.app.homeserver"]

CONFIGFILE = "homeserver.yaml"
PIDFILE = "homeserver.pid"

GREEN = "\x1b[1;32m"
NORMAL = "\x1b[m"


def start():
    if not os.path.exists(CONFIGFILE):
        sys.stderr.write(
            "No config file found\n"
            "To generate a config file, run '%s -c %s --generate-config"
            " --server-name=<server name>'\n" % (
                " ".join(SYNAPSE), CONFIGFILE
            )
        )
        sys.exit(1)
    print "Starting ...",
    args = SYNAPSE
    args.extend(["--daemonize", "-c", CONFIGFILE, "--pid-file", PIDFILE])
    subprocess.check_call(args)
    print GREEN + "started" + NORMAL


def stop():
    if os.path.exists(PIDFILE):
        pid = int(open(PIDFILE).read())
        os.kill(pid, signal.SIGTERM)
        print GREEN + "stopped" + NORMAL


def main():
    action = sys.argv[1] if sys.argv[1:] else "usage"
    if action == "start":
        start()
    elif action == "stop":
        stop()
    elif action == "restart":
        stop()
        start()
    else:
        sys.stderr.write("Usage: %s [start|stop|restart]\n" % (sys.argv[0],))
        sys.exit(1)


if __name__ == "__main__":
    main()
