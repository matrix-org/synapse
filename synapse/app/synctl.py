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
import ruamel.yaml

SYNAPSE = ["python", "-B", "-m", "synapse.app.homeserver"]

CONFIGFILE = "homeserver.yaml"

GREEN = "\x1b[1;32m"
NORMAL = "\x1b[m"

if not os.path.exists(CONFIGFILE):
    sys.stderr.write(
        "No config file found\n"
        "To generate a config file, run '%s -c %s --generate-config"
        " --server-name=<server name>'\n" % (
            " ".join(SYNAPSE), CONFIGFILE
        )
    )
    sys.exit(1)

CONFIG = ruamel.yaml.load(open(CONFIGFILE), ruamel.yaml.RoundTripLoader)
PIDFILE = CONFIG["pid_file"]


def start():
    print "Starting ...",
    args = SYNAPSE
    args.extend(["--daemonize", "-c", CONFIGFILE])
    subprocess.check_call(args)
    print GREEN + "started" + NORMAL


def stop():
    if os.path.exists(PIDFILE):
        pid = int(open(PIDFILE).read())
        os.kill(pid, signal.SIGTERM)
        print GREEN + "stopped" + NORMAL

"""
Very basic tool for editing the synapse config from the cli
Supports setting the value of root level keys and appending to arrays
Does not support nested keys, removing items from arrays or removing keys.
Uses ruamel.yaml feature that preserves comments and formatting (although
does quoting slightly differently)
"""
def cfgedit(args):
    if len(args) < 3:
        raise Exception(
            "Usage: synctl cfgedit config_option = value"
            "       synctl cfgedit config_listoption += value"
        )
    key = args[0]
    op = args[1]
    val = args[2]
    if op == '+=':
        if CONFIG[key] and not isinstance(CONFIG[key], list):
            raise Exception("%s is not a list" % key)
        if not key in CONFIG:
            CONFIG[key] = []
        CONFIG[key].append(val)
    elif op == '=':
        CONFIG[key] = val
    else:
        raise Exception("Unsupported operator: %s" % op)

    fp = open(CONFIGFILE, 'w')
    fp.write(ruamel.yaml.dump(CONFIG, Dumper=ruamel.yaml.RoundTripDumper))
    fp.close()


def main():
    action = sys.argv[1] if sys.argv[1:] else "usage"
    if action == "start":
        start()
    elif action == "stop":
        stop()
    elif action == "restart":
        stop()
        start()
    elif action == 'cfgedit':
        cfgedit(sys.argv[2:])
    else:
        sys.stderr.write("Usage: %s [start|stop|restart]\n" % (sys.argv[0],))
        sys.exit(1)


if __name__ == "__main__":
    main()
