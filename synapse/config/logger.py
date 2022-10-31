# Copyright 2014-2016 OpenMarket Ltd
# Copyright 2021 The Matrix.org Foundation C.I.C.
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
from typing import TYPE_CHECKING, Any, Dict, Optional

import yaml
from zope.interface import implementer

from twisted.logger import (
    ILogObserver,
    LogBeginner,
    STDLibLogObserver,
    eventAsText,
    globalLogBeginner,
)

from synapse.logging.context import LoggingContextFilter
from synapse.logging.filter import MetadataFilter
from synapse.types import JsonDict

from ..util import SYNAPSE_VERSION
from ._base import Config, ConfigError

if TYPE_CHECKING:
    from synapse.config.homeserver import HomeServerConfig
    from synapse.server import HomeServer

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
# [1]: https://docs.python.org/3/library/logging.config.html#configuration-dictionary-schema
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

    # Default to buffering writes to log file for efficiency.
    # WARNING/ERROR logs will still be flushed immediately, but there will be a
    # delay (of up to `period` seconds, or until the buffer is full with
    # `capacity` messages) before INFO/DEBUG logs get written.
    buffer:
        class: synapse.logging.handlers.PeriodicallyFlushingMemoryHandler
        target: file

        # The capacity is the maximum number of log lines that are buffered
        # before being written to disk. Increasing this will lead to better
        # performance, at the expensive of it taking longer for log lines to
        # be written to disk.
        # This parameter is required.
        capacity: 10

        # Logs with a level at or above the flush level will cause the buffer to
        # be flushed immediately.
        # Default value: 40 (ERROR)
        # Other values: 50 (CRITICAL), 30 (WARNING), 20 (INFO), 10 (DEBUG)
        flushLevel: 30  # Flush immediately for WARNING logs and higher

        # The period of time, in seconds, between forced flushes.
        # Messages will not be delayed for longer than this time.
        # Default value: 5 seconds
        period: 5

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

STRUCTURED_ERROR = """\
Support for the structured configuration option was removed in Synapse 1.54.0.
You should instead use the standard logging configuration. See
https://matrix-org.github.io/synapse/v1.54/structured_logging.html
"""


class LoggingConfig(Config):
    section = "logging"

    def read_config(self, config: JsonDict, **kwargs: Any) -> None:
        if config.get("log_file"):
            raise ConfigError(LOG_FILE_ERROR)
        self.log_config = self.abspath(config.get("log_config"))
        self.no_redirect_stdio = config.get("no_redirect_stdio", False)

    def generate_config_section(
        self, config_dir_path: str, server_name: str, **kwargs: Any
    ) -> str:
        log_config = os.path.join(config_dir_path, server_name + ".log.config")
        return (
            """\
        log_config: "%(log_config)s"
        """
            % locals()
        )

    def read_arguments(self, args: argparse.Namespace) -> None:
        if args.no_redirect_stdio is not None:
            self.no_redirect_stdio = args.no_redirect_stdio
        if args.log_file is not None:
            raise ConfigError(LOG_FILE_ERROR)

    @staticmethod
    def add_arguments(parser: argparse.ArgumentParser) -> None:
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

    def generate_files(self, config: Dict[str, Any], config_dir_path: str) -> None:
        log_config = config.get("log_config")
        if log_config and not os.path.exists(log_config):
            log_file = self.abspath("homeserver.log")
            print(
                "Generating log config file %s which will log to %s"
                % (log_config, log_file)
            )
            with open(log_config, "w") as log_config_file:
                log_config_file.write(DEFAULT_LOG_CONFIG.substitute(log_file=log_file))


def _setup_stdlib_logging(
    config: "HomeServerConfig", log_config_path: Optional[str], logBeginner: LogBeginner
) -> None:
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
    log_metadata_filter = MetadataFilter({"server_name": config.server.server_name})
    old_factory = logging.getLogRecordFactory()

    def factory(*args: Any, **kwargs: Any) -> logging.LogRecord:
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

    # If the old structured logging configuration is being used, raise an error.
    if "structured" in log_config and log_config.get("structured"):
        raise ConfigError(STRUCTURED_ERROR)

    logging.config.dictConfig(log_config)


def _reload_logging_config(log_config_path: Optional[str]) -> None:
    """
    Reload the log configuration from the file and apply it.
    """
    # If no log config path was given, it cannot be reloaded.
    if log_config_path is None:
        return

    _load_logging_config(log_config_path)
    logging.info("Reloaded log config from %s due to SIGHUP", log_config_path)


def setup_logging(
    hs: "HomeServer",
    config: "HomeServerConfig",
    use_worker_options: bool = False,
    logBeginner: LogBeginner = globalLogBeginner,
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
    from twisted.internet import reactor

    log_config_path = (
        config.worker.worker_log_config
        if use_worker_options
        else config.logging.log_config
    )

    # Perform one-time logging configuration.
    _setup_stdlib_logging(config, log_config_path, logBeginner=logBeginner)
    # Add a SIGHUP handler to reload the logging configuration, if one is available.
    from synapse.app import _base as appbase

    appbase.register_sighup(_reload_logging_config, log_config_path)

    # Log immediately so we can grep backwards.
    logging.warning("***** STARTING SERVER *****")
    logging.warning(
        "Server %s version %s",
        sys.argv[0],
        SYNAPSE_VERSION,
    )
    logging.info("Server hostname: %s", config.server.server_name)
    logging.info("Instance name: %s", hs.get_instance_name())
    logging.info("Twisted reactor: %s", type(reactor).__name__)
