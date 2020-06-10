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
import logging
import logging.config
import os
import sys
from string import Template

import yaml

from twisted.logger import (
    ILogObserver,
    LogBeginner,
    STDLibLogObserver,
    globalLogBeginner,
)

import synapse
from synapse.app import _base as appbase
from synapse.logging._structured import (
    reload_structured_logging,
    setup_structured_logging,
)
from synapse.logging.context import LoggingContextFilter
from synapse.util.versionstring import get_version_string

from ._base import Config, ConfigError

DEFAULT_LOG_CONFIG = Template(
    """\
# Log configuration for Synapse.
#
# This is a YAML file containing a standard Python logging configuration
# dictionary. See [1] for details on the valid settings.
#
# [1]: https://docs.python.org/3.7/library/logging.config.html#configuration-dictionary-schema

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
    synapse.storage.SQL:
        # beware: increasing this to DEBUG will make synapse log sensitive
        # information such as access tokens.
        level: INFO

root:
    level: INFO
    handlers: [file, console]

disable_existing_loggers: false
"""
)

LOG_FILE_ERROR = """\
Support for the log_file configuration option and --log-file command-line option was
removed in Synapse 1.3.0. You should instead set up a separate log configuration file.
"""


class LoggingConfig(Config):
    section = "logging"

    def read_config(self, config, **kwargs):
        if config.get("log_file"):
            raise ConfigError(LOG_FILE_ERROR)
        self.log_config = self.abspath(config.get("log_config"))
        self.no_redirect_stdio = config.get("no_redirect_stdio", False)

    def generate_config_section(self, config_dir_path, server_name, **kwargs):
        log_config = os.path.join(config_dir_path, server_name + ".log.config")
        return (
            """\
        ## Logging ##

        # A yaml python logging config file as described by
        # https://docs.python.org/3.7/library/logging.config.html#configuration-dictionary-schema
        #
        log_config: "%(log_config)s"
        """
            % locals()
        )

    def read_arguments(self, args):
        if args.no_redirect_stdio is not None:
            self.no_redirect_stdio = args.no_redirect_stdio
        if args.log_file is not None:
            raise ConfigError(LOG_FILE_ERROR)

    @staticmethod
    def add_arguments(parser):
        logging_group = parser.add_argument_group("logging")
        logging_group.add_argument(
            "-n",
            "--no-redirect-stdio",
            action="store_true",
            default=None,
            help="Do not redirect stdout/stderr to the log",
        )

        logging_group.add_argument(
            "-f", "--log-file", dest="log_file", help=argparse.SUPPRESS,
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


def _setup_stdlib_logging(config, log_config, logBeginner: LogBeginner):
    """
    Set up Python stdlib logging.
    """
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
        logging.config.dictConfig(log_config)

    # Route Twisted's native logging through to the standard library logging
    # system.
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

    logBeginner.beginLoggingTo([_log], redirectStandardIO=not config.no_redirect_stdio)
    if not config.no_redirect_stdio:
        print("Redirected stdout/stderr to logs")

    return observer


def _reload_stdlib_logging(*args, log_config=None):
    logger = logging.getLogger("")

    if not log_config:
        logger.warning("Reloaded a blank config?")

    logging.config.dictConfig(log_config)


def setup_logging(
    hs, config, use_worker_options=False, logBeginner: LogBeginner = globalLogBeginner
) -> ILogObserver:
    """
    Set up the logging subsystem.

    Args:
        config (LoggingConfig | synapse.config.workers.WorkerConfig):
            configuration data

        use_worker_options (bool): True to use the 'worker_log_config' option
            instead of 'log_config'.

        logBeginner: The Twisted logBeginner to use.

    Returns:
        The "root" Twisted Logger observer, suitable for sending logs to from a
        Logger instance.
    """
    log_config = config.worker_log_config if use_worker_options else config.log_config

    def read_config(*args, callback=None):
        if log_config is None:
            return None

        with open(log_config, "rb") as f:
            log_config_body = yaml.safe_load(f.read())

        if callback:
            callback(log_config=log_config_body)
            logging.info("Reloaded log config from %s due to SIGHUP", log_config)

        return log_config_body

    log_config_body = read_config()

    if log_config_body and log_config_body.get("structured") is True:
        logger = setup_structured_logging(
            hs, config, log_config_body, logBeginner=logBeginner
        )
        appbase.register_sighup(read_config, callback=reload_structured_logging)
    else:
        logger = _setup_stdlib_logging(config, log_config_body, logBeginner=logBeginner)
        appbase.register_sighup(read_config, callback=_reload_stdlib_logging)

    # make sure that the first thing we log is a thing we can grep backwards
    # for
    logging.warning("***** STARTING SERVER *****")
    logging.warning("Server %s version %s", sys.argv[0], get_version_string(synapse))
    logging.info("Server hostname: %s", config.server_name)
    logging.info("Instance name: %s", hs.get_instance_name())

    return logger
