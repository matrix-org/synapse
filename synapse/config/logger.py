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
import threading
from string import Template

import yaml
from zope.interface import implementer

from twisted.logger import (
    ILogObserver,
    LogBeginner,
    STDLibLogObserver,
    eventAsText,
    globalLogBeginner,
)

import synapse
from synapse.logging._structured import setup_structured_logging
from synapse.logging.context import LoggingContextFilter
from synapse.logging.filter import MetadataFilter
from synapse.util.versionstring import get_version_string

from ._base import Config, ConfigError

DEFAULT_LOG_CONFIG = Template(
    """\
# Log configuration for Synapse.
#
# This is a YAML file containing a standard Python logging configuration
# dictionary. See [1] for details on the valid settings.
#
# Synapse also supports structured logging for machine readable logs which can
# be ingested by ELK stacks. See [2] for details.
#
# [1]: https://docs.python.org/3.7/library/logging.config.html#configuration-dictionary-schema
# [2]: https://matrix-org.github.io/synapse/latest/structured_logging.html

version: 1

formatters:
    precise:
        format: '%(asctime)s - %(name)s - %(lineno)d - %(levelname)s - \
%(request)s - %(message)s'

handlers:
    file:
        class: logging.handlers.TimedRotatingFileHandler
        formatter: precise
        filename: ${log_file}
        when: midnight
        backupCount: 3  # Does not include the current log file.
        encoding: utf8

    # Default to buffering writes to log file for efficiency. This means that
    # will be a delay for INFO/DEBUG logs to get written, but WARNING/ERROR
    # logs will still be flushed immediately.
    buffer:
        class: logging.handlers.MemoryHandler
        target: file
        # The capacity is the number of log lines that are buffered before
        # being written to disk. Increasing this will lead to better
        # performance, at the expensive of it taking longer for log lines to
        # be written to disk.
        capacity: 10
        flushLevel: 30  # Flush for WARNING logs as well

    # A handler that writes logs to stderr. Unused by default, but can be used
    # instead of "buffer" and "file" in the logger handlers.
    console:
        class: logging.StreamHandler
        formatter: precise

loggers:
    synapse.storage.SQL:
        # beware: increasing this to DEBUG will make synapse log sensitive
        # information such as access tokens.
        level: INFO

    twisted:
        # We send the twisted logging directly to the file handler,
        # to work around https://github.com/matrix-org/synapse/issues/3471
        # when using "buffer" logger. Use "console" to log to stderr instead.
        handlers: [file]
        propagate: false

root:
    level: INFO

    # Write logs to the `buffer` handler, which will buffer them together in memory,
    # then write them to a file.
    #
    # Replace "buffer" with "console" to log to stderr instead. (Note that you'll
    # also need to update the configuration for the `twisted` logger above, in
    # this case.)
    #
    handlers: [buffer]

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
            "-f",
            "--log-file",
            dest="log_file",
            help=argparse.SUPPRESS,
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


def _setup_stdlib_logging(config, log_config_path, logBeginner: LogBeginner) -> None:
    """
    Set up Python standard library logging.
    """
    if log_config_path is None:
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
        logger.addHandler(handler)
    else:
        # Load the logging configuration.
        _load_logging_config(log_config_path)

    # We add a log record factory that runs all messages through the
    # LoggingContextFilter so that we get the context *at the time we log*
    # rather than when we write to a handler. This can be done in config using
    # filter options, but care must when using e.g. MemoryHandler to buffer
    # writes.

    log_context_filter = LoggingContextFilter()
    log_metadata_filter = MetadataFilter({"server_name": config.server_name})
    old_factory = logging.getLogRecordFactory()

    def factory(*args, **kwargs):
        record = old_factory(*args, **kwargs)
        log_context_filter.filter(record)
        log_metadata_filter.filter(record)
        return record

    logging.setLogRecordFactory(factory)

    # Route Twisted's native logging through to the standard library logging
    # system.
    observer = STDLibLogObserver()

    threadlocal = threading.local()

    @implementer(ILogObserver)
    def _log(event: dict) -> None:
        if "log_text" in event:
            if event["log_text"].startswith("DNSDatagramProtocol starting on "):
                return

            if event["log_text"].startswith("(UDP Port "):
                return

            if event["log_text"].startswith("Timing out client"):
                return

        # this is a workaround to make sure we don't get stack overflows when the
        # logging system raises an error which is written to stderr which is redirected
        # to the logging system, etc.
        if getattr(threadlocal, "active", False):
            # write the text of the event, if any, to the *real* stderr (which may
            # be redirected to /dev/null, but there's not much we can do)
            try:
                event_text = eventAsText(event)
                print("logging during logging: %s" % event_text, file=sys.__stderr__)
            except Exception:
                # gah.
                pass
            return

        try:
            threadlocal.active = True
            return observer(event)
        finally:
            threadlocal.active = False

    logBeginner.beginLoggingTo([_log], redirectStandardIO=False)


def _load_logging_config(log_config_path: str) -> None:
    """
    Configure logging from a log config path.
    """
    with open(log_config_path, "rb") as f:
        log_config = yaml.safe_load(f.read())

    if not log_config:
        logging.warning("Loaded a blank logging config?")

    # If the old structured logging configuration is being used, convert it to
    # the new style configuration.
    if "structured" in log_config and log_config.get("structured"):
        log_config = setup_structured_logging(log_config)

    logging.config.dictConfig(log_config)


def _reload_logging_config(log_config_path):
    """
    Reload the log configuration from the file and apply it.
    """
    # If no log config path was given, it cannot be reloaded.
    if log_config_path is None:
        return

    _load_logging_config(log_config_path)
    logging.info("Reloaded log config from %s due to SIGHUP", log_config_path)


def setup_logging(
    hs, config, use_worker_options=False, logBeginner: LogBeginner = globalLogBeginner
) -> None:
    """
    Set up the logging subsystem.

    Args:
        config (LoggingConfig | synapse.config.worker.WorkerConfig):
            configuration data

        use_worker_options (bool): True to use the 'worker_log_config' option
            instead of 'log_config'.

        logBeginner: The Twisted logBeginner to use.

    """
    log_config_path = (
        config.worker_log_config if use_worker_options else config.log_config
    )

    # Perform one-time logging configuration.
    _setup_stdlib_logging(config, log_config_path, logBeginner=logBeginner)
    # Add a SIGHUP handler to reload the logging configuration, if one is available.
    from synapse.app import _base as appbase

    appbase.register_sighup(_reload_logging_config, log_config_path)

    # Log immediately so we can grep backwards.
    logging.warning("***** STARTING SERVER *****")
    logging.warning("Server %s version %s", sys.argv[0], get_version_string(synapse))
    logging.info("Server hostname: %s", config.server_name)
    logging.info("Instance name: %s", hs.get_instance_name())
