# -*- coding: utf-8 -*-
# Copyright 2017 New Vector Ltd
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

import gc
import logging
import sys

try:
    import affinity
except Exception:
    affinity = None

from daemonize import Daemonize
from synapse.util import PreserveLoggingContext
from synapse.util.rlimit import change_resource_limit
from twisted.internet import reactor


def start_worker_reactor(appname, config):
    """ Run the reactor in the main process

    Daemonizes if necessary, and then configures some resources, before starting
    the reactor. Pulls configuration from the 'worker' settings in 'config'.

    Args:
        appname (str): application name which will be sent to syslog
        config (synapse.config.Config): config object
    """

    logger = logging.getLogger(config.worker_app)

    start_reactor(
        appname,
        config.soft_file_limit,
        config.gc_thresholds,
        config.worker_pid_file,
        config.worker_daemonize,
        config.worker_cpu_affinity,
        logger,
    )


def start_reactor(
        appname,
        soft_file_limit,
        gc_thresholds,
        pid_file,
        daemonize,
        cpu_affinity,
        logger,
):
    """ Run the reactor in the main process

    Daemonizes if necessary, and then configures some resources, before starting
    the reactor

    Args:
        appname (str): application name which will be sent to syslog
        soft_file_limit (int):
        gc_thresholds:
        pid_file (str): name of pid file to write to if daemonize is True
        daemonize (bool): true to run the reactor in a background process
        cpu_affinity (int|None): cpu affinity mask
        logger (logging.Logger): logger instance to pass to Daemonize
    """

    def run():
        # make sure that we run the reactor with the sentinel log context,
        # otherwise other PreserveLoggingContext instances will get confused
        # and complain when they see the logcontext arbitrarily swapping
        # between the sentinel and `run` logcontexts.
        with PreserveLoggingContext():
            logger.info("Running")
            if cpu_affinity is not None:
                if not affinity:
                    quit_with_error(
                        "Missing package 'affinity' required for cpu_affinity\n"
                        "option\n\n"
                        "Install by running:\n\n"
                        "   pip install affinity\n\n"
                    )
                logger.info("Setting CPU affinity to %s" % cpu_affinity)
                affinity.set_process_affinity_mask(0, cpu_affinity)
            change_resource_limit(soft_file_limit)
            if gc_thresholds:
                gc.set_threshold(*gc_thresholds)
            reactor.run()

    if daemonize:
        daemon = Daemonize(
            app=appname,
            pid=pid_file,
            action=run,
            auto_close_fds=False,
            verbose=True,
            logger=logger,
        )
        daemon.start()
    else:
        run()


def quit_with_error(error_string):
    message_lines = error_string.split("\n")
    line_length = max([len(l) for l in message_lines if len(l) < 80]) + 2
    sys.stderr.write("*" * line_length + '\n')
    for line in message_lines:
        sys.stderr.write(" %s\n" % (line.rstrip(),))
    sys.stderr.write("*" * line_length + '\n')
    sys.exit(1)
