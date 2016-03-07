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

import sys
import os
import os.path
import subprocess
import signal
import yaml

SYNAPSE = ["python", "-B", "-m", "synapse.app.homeserver"]

GREEN = "\x1b[1;32m"
RED = "\x1b[1;31m"
NORMAL = "\x1b[m"


def start(configfile):
    print ("Starting ...")
    args = SYNAPSE
    args.extend(["--daemonize", "-c", configfile])

    try:
        subprocess.check_call(args)
        print (GREEN + "started" + NORMAL)
    except subprocess.CalledProcessError as e:
        print (
            RED +
            "error starting (exit code: %d); see above for logs" % e.returncode +
            NORMAL
        )


def stop(pidfile):
    if os.path.exists(pidfile):
        pid = int(open(pidfile).read())
        os.kill(pid, signal.SIGTERM)
        print (GREEN + "stopped" + NORMAL)


def main():
    configfile = sys.argv[2] if len(sys.argv) == 3 else "homeserver.yaml"

    if not os.path.exists(configfile):
        sys.stderr.write(
            "No config file found\n"
            "To generate a config file, run '%s -c %s --generate-config"
            " --server-name=<server name>'\n" % (
                " ".join(SYNAPSE), configfile
            )
        )
        sys.exit(1)

    config = yaml.load(open(configfile))
    pidfile = config["pid_file"]

    action = sys.argv[1] if sys.argv[1:] else "usage"
    if action == "start":
        start(configfile)
    elif action == "stop":
        stop(pidfile)
    elif action == "restart":
        stop(pidfile)
        start(configfile)
    else:
        sys.stderr.write("Usage: %s [start|stop|restart] [configfile]\n" % (sys.argv[0],))
        sys.exit(1)


if __name__ == "__main__":
    main()
