# -*- coding: utf-8 -*-
# Copyright 2019 The Matrix.org Foundation C.I.C.
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
import sys

import attr
from constantly import NamedConstant, Names, ValueConstant, Values
from zope.interface import implementer

from twisted.logger import (
    FileLogObserver,
    FilteringLogObserver,
    ILogObserver,
    Logger,
    LogLevel,
    LogLevelFilterPredicate,
    LogPublisher,
    eventAsText,
    globalLogBeginner,
    jsonFileLogObserver,
)

from synapse.config._base import ConfigError
from synapse.logging.context import LoggingContext


def stdlib_log_level_to_twisted(level):
    """
    Convert a stdlib log level to Twisted's log level.
    """
    lvl = level.lower().replace("warning", "warn")
    return LogLevel.levelWithName(lvl)


@attr.s
@implementer(ILogObserver)
class LogContextObserver(object):
    """
    An ILogObserver which adds Synapse-specific log context information.

    Attributes:
        observer (ILogObserver): The target parent observer.
    """

    observer = attr.ib()

    def __call__(self, event):
        """
        Consume a log event and emit it to the parent observer after filtering
        and adding log context information.

        Args:
            event (dict)
        """
        # Filter out some useless events that Twisted outputs
        if "log_text" in event:
            if event["log_text"].startswith("DNSDatagramProtocol starting on "):
                return

            if event["log_text"].startswith("(UDP Port "):
                return

            if event["log_text"].startswith("Timing out client"):
                return

        context = LoggingContext.current_context()

        # Copy the context information to the log event.
        if context is not None:
            context.copy_to_twisted_log_entry(event)
        else:
            # If there's no logging context, not even the root one, we might be
            # starting up or it might be from non-Synapse code. Log it as if it
            # came from the root logger.
            event["request"] = None
            event["scope"] = None

        return self.observer(event)


class PythonStdlibToTwistedLogger(logging.Handler):
    """
    Transform a Python stdlib log message into a Twisted one.
    """

    def __init__(self, observer, *args, **kwargs):
        """
        Args:
            observer (ILogObserver): A Twisted logging observer.
            *args, **kwargs: Args/kwargs to be passed to logging.Handler.
        """
        self.observer = observer
        super().__init__(*args, **kwargs)

    def emit(self, record):
        """
        Emit a record to Twisted's observer.

        Args:
            record (logging.LogRecord)
        """

        self.observer(
            {
                "log_time": record.created,
                "log_text": record.getMessage(),
                "log_format": "{log_text}",
                "log_namespace": record.name,
                "log_level": stdlib_log_level_to_twisted(record.levelname),
            }
        )


def SynapseFileLogObserver(outFile):
    """
    A log observer that formats events like the traditional log formatter and
    sends them to `outFile`.

    Args:
        outFile (file object): The file object to write to.
    """

    def formatEvent(_event):
        event = _event.copy()
        event["log_level"] = event["log_level"].name.upper()
        event["log_format"] = (
            "- {log_namespace} - {log_level} - {request} - "
            + event.get("log_format", "{log_text}")
        )
        return eventAsText(event, includeSystem=False) + "\n"

    return FileLogObserver(outFile, formatEvent)


class LoggingOutputType(Names):
    CONSOLE = NamedConstant()
    JSON = NamedConstant()
    FLUENTD = NamedConstant()


class OutputPipeType(Values):
    stdout = ValueConstant(sys.__stdout__)
    stderr = ValueConstant(sys.__stderr__)


@attr.s
class HandlerConfiguration(object):
    name = attr.ib()
    type = attr.ib()
    location = attr.ib()


def parse_handler_configs(config):
    """
    Parse the logging format version 2 handler section.

    Args:
        config (dict): A logging format v2 dictionary.

    Yields:
        HandlerConfiguration instances.

    Raises:
        ConfigError: If any of the handler configuration items are invalid.
    """
    for name, config in config.get("handlers").items():
        logging_type = None

        if "type" not in config and "class" in config:
            # Handle the old "class": style.
            if config["class"] == "logging.StreamHandler":
                yield (
                    HandlerConfiguration(
                        name=name,
                        type=LoggingOutputType.CONSOLE,
                        location=sys.__stdout__,
                    )
                )
            else:
                raise ConfigError(
                    "The logging class %s is not supported in logging format 2."
                    % (config["class"],)
                )
        elif "type" in config:
            logging_type = LoggingOutputType.lookupByName(config["type"].upper())

            if logging_type in [LoggingOutputType.CONSOLE, LoggingOutputType.JSON]:
                location = config.get("location")
                if location is None or location not in ["stdout", "stderr"]:
                    raise ConfigError(
                        (
                            "The %s handler needs the 'location' key set to "
                            "either 'stdout' or 'stderr'."
                        )
                    )

                yield HandlerConfiguration(
                    name=name,
                    type=logging_type,
                    location=OutputPipeType.lookupByName(location).value,
                )
        else:
            raise ConfigError("Handlers need to have either a 'type' or 'class' key.")


def setup_structured_logging(config, log_config):
    """
    Set up Twisted's structured logging system.

    Args:
        config (HomeserverConfig): The configuration of the Synapse homeserver.
        log_config (dict): The log configuration to use.
    """
    if config.no_redirect_stdio:
        raise ConfigError(
            "no_redirect_stdio cannot be defined using log_config version 2."
        )

    logger = Logger()

    observers = []

    for observer in parse_handler_configs(log_config):
        if observer.type == LoggingOutputType.CONSOLE:
            logger.debug("Starting up the {name} console logger", name=observer.name)
            observers.append(SynapseFileLogObserver(observer.location))
        if observer.type == LoggingOutputType.JSON:
            logger.debug("Starting up the {name} JSON logger", name=observer.name)
            observers.append(jsonFileLogObserver(observer.location))

    publisher = LogPublisher(*observers)
    log_filter = LogLevelFilterPredicate()

    for namespace, config in log_config.get("loggers", {}).items():
        log_filter.setLogLevelForNamespace(
            namespace, stdlib_log_level_to_twisted(log_config.get("level", "INFO"))
        )

    f = FilteringLogObserver(publisher, [log_filter])
    lco = LogContextObserver(f)
    stuff_into_twisted = PythonStdlibToTwistedLogger(lco)

    stdliblogger = logging.getLogger("")
    stdliblogger.setLevel(logging.DEBUG)
    stdliblogger.addHandler(stuff_into_twisted)

    # Redirecting stdio is important here, especially if there's a JSON
    # outputter!
    globalLogBeginner.beginLoggingTo([lco], redirectStandardIO=True)


def reload_structured_logging(*args, log_config=None):
    # TODO: Reload the structured logging system. Since we don't implement any
    # sort of file rotation, we don't need to worry about doing that here.
    pass
