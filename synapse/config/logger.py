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
import logging
import logging.config
import os
import sys
from string import Template

import yaml

from twisted.logger import STDLibLogObserver, globalLogBeginner

import synapse
from synapse.app import _base as appbase
from synapse.logging.context import LoggingContextFilter
from synapse.util.versionstring import get_version_string

from ._base import Config

DEFAULT_LOG_CONFIG = Template(
    """
version: 1

formatters:
    precise:
        format: '%(asctime)s - %(name)s - %(lineno)d - %(levelname)s - \
%(request)s - %(message)s'

filters:
    context:
        (): synapse.logging.context.LoggingContextFilter
        request: ""

handlers:
    file:
        class: logging.handlers.RotatingFileHandler
        formatter: precise
        filename: ${log_file}
        maxBytes: 104857600
        backupCount: 10
        filters: [context]
        encoding: utf8
    console:
        class: logging.StreamHandler
        formatter: precise
        filters: [context]

loggers:
    synapse:
        level: INFO

    synapse.storage.SQL:
        # beware: increasing this to DEBUG will make synapse log sensitive
        # information such as access tokens.
        level: INFO

root:
    level: INFO
    handlers: [file, console]
"""
)


class LoggingConfig(Config):
    def read_config(self, config, **kwargs):
        self.log_config = self.abspath(config.get("log_config"))

    def generate_config_section(self, config_dir_path, server_name, **kwargs):
        log_config = os.path.join(config_dir_path, server_name + ".log.config")
        return (
            """\
        ## Logging ##

        # A yaml python logging config file
        #
        log_config: "%(log_config)s"
        """
            % locals()
        )

    def generate_files(self, config, config_dir_path):
        log_config = config.get("log_config")
        if log_config and not os.path.exists(log_config):
            log_file = self.abspath("homeserver.log")
            print(
                "Generating log config file %s which will log to %s"
                % (log_config, log_file)
            )
            with open(log_config, "w") as log_config_file:
                log_config_file.write(DEFAULT_LOG_CONFIG.substitute(log_file=log_file))


def setup_logging(config, use_worker_options=False):
    """ Set up python logging

    Args:
        config (LoggingConfig | synapse.config.workers.WorkerConfig):
            configuration data

        use_worker_options (bool): True to use the 'worker_log_config' option
            instead of 'log_config'.

        register_sighup (func | None): Function to call to register a
            sighup handler.
    """
    log_config = config.worker_log_config if use_worker_options else config.log_config

    if log_config is None:
        log_format = (
            "%(asctime)s - %(name)s - %(lineno)d - %(levelname)s - %(request)s"
            " - %(message)s"
        )

        logger = logging.getLogger("")
        logger.setLevel(logging.INFO)
        logging.getLogger("synapse.storage.SQL").setLevel(logging.INFO)

        formatter = logging.Formatter(log_format)

        handler = logging.StreamHandler()
        handler.setFormatter(formatter)
        handler.addFilter(LoggingContextFilter(request=""))
        logger.addHandler(handler)
    else:

        def load_log_config():
            with open(log_config, "r") as f:
                logging.config.dictConfig(yaml.safe_load(f))

        def sighup(*args):
            # it might be better to use a file watcher or something for this.
            load_log_config()
            logging.info("Reloaded log config from %s due to SIGHUP", log_config)

        load_log_config()
        appbase.register_sighup(sighup)

    # make sure that the first thing we log is a thing we can grep backwards
    # for
    logging.warn("***** STARTING SERVER *****")
    logging.warn("Server %s version %s", sys.argv[0], get_version_string(synapse))
    logging.info("Server hostname: %s", config.server_name)

    # It's critical to point twisted's internal logging somewhere, otherwise it
    # stacks up and leaks kup to 64K object;
    # see: https://twistedmatrix.com/trac/ticket/8164
    #
    # Routing to the python logging framework could be a performance problem if
    # the handlers blocked for a long time as python.logging is a blocking API
    # see https://twistedmatrix.com/documents/current/core/howto/logger.html
    # filed as https://github.com/matrix-org/synapse/issues/1727
    #
    # However this may not be too much of a problem if we are just writing to a file.
    observer = STDLibLogObserver()

    def _log(event):

        if "log_text" in event:
            if event["log_text"].startswith("DNSDatagramProtocol starting on "):
                return

            if event["log_text"].startswith("(UDP Port "):
                return

            if event["log_text"].startswith("Timing out client"):
                return

        return observer(event)

    globalLogBeginner.beginLoggingTo([_log], redirectStandardIO=True)
