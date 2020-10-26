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

"""
Log formatters that output terse JSON.
"""

import json
from typing import IO

from twisted.logger import FileLogObserver

from synapse.logging._remote import TCPLogObserver

_encoder = json.JSONEncoder(ensure_ascii=False, separators=(",", ":"))


def flatten_event(event: dict, metadata: dict, include_time: bool = False):
    """
    Flatten a Twisted logging event to an dictionary capable of being sent
    as a log event to a logging aggregation system.

    The format is vastly simplified and is not designed to be a "human readable
    string" in the sense that traditional logs are. Instead, the structure is
    optimised for searchability and filtering, with human-understandable log
    keys.

    Args:
        event (dict): The Twisted logging event we are flattening.
        metadata (dict): Additional data to include with each log message. This
            can be information like the server name. Since the target log
            consumer does not know who we are other than by host IP, this
            allows us to forward through static information.
        include_time (bool): Should we include the `time` key? If False, the
            event time is stripped from the event.
    """
    new_event = {}

    # If it's a failure, make the new event's log_failure be the traceback text.
    if "log_failure" in event:
        new_event["log_failure"] = event["log_failure"].getTraceback()

    # If it's a warning, copy over a string representation of the warning.
    if "warning" in event:
        new_event["warning"] = str(event["warning"])

    # Stdlib logging events have "log_text" as their human-readable portion,
    # Twisted ones have "log_format". For now, include the log_format, so that
    # context only given in the log format (e.g. what is being logged) is
    # available.
    if "log_text" in event:
        new_event["log"] = event["log_text"]
    else:
        new_event["log"] = event["log_format"]

    # We want to include the timestamp when forwarding over the network, but
    # exclude it when we are writing to stdout. This is because the log ingester
    # (e.g. logstash, fluentd) can add its own timestamp.
    if include_time:
        new_event["time"] = round(event["log_time"], 2)

    # Convert the log level to a textual representation.
    new_event["level"] = event["log_level"].name.upper()

    # Ignore these keys, and do not transfer them over to the new log object.
    # They are either useless (isError), transferred manually above (log_time,
    # log_level, etc), or contain Python objects which are not useful for output
    # (log_logger, log_source).
    keys_to_delete = [
        "isError",
        "log_failure",
        "log_format",
        "log_level",
        "log_logger",
        "log_source",
        "log_system",
        "log_time",
        "log_text",
        "observer",
        "warning",
    ]

    # If it's from the Twisted legacy logger (twisted.python.log), it adds some
    # more keys we want to purge.
    if event.get("log_namespace") == "log_legacy":
        keys_to_delete.extend(["message", "system", "time"])

    # Rather than modify the dictionary in place, construct a new one with only
    # the content we want. The original event should be considered 'frozen'.
    for key in event.keys():

        if key in keys_to_delete:
            continue

        if isinstance(event[key], (str, int, bool, float)) or event[key] is None:
            # If it's a plain type, include it as is.
            new_event[key] = event[key]
        else:
            # If it's not one of those basic types, write out a string
            # representation. This should probably be a warning in development,
            # so that we are sure we are only outputting useful data.
            new_event[key] = str(event[key])

    # Add the metadata information to the event (e.g. the server_name).
    new_event.update(metadata)

    return new_event


def TerseJSONToConsoleLogObserver(outFile: IO[str], metadata: dict) -> FileLogObserver:
    """
    A log observer that formats events to a flattened JSON representation.

    Args:
        outFile: The file object to write to.
        metadata: Metadata to be added to each log object.
    """

    def formatEvent(_event: dict) -> str:
        flattened = flatten_event(_event, metadata)
        return _encoder.encode(flattened) + "\n"

    return FileLogObserver(outFile, formatEvent)


def TerseJSONToTCPLogObserver(
    hs, host: str, port: int, metadata: dict, maximum_buffer: int
) -> FileLogObserver:
    """
    A log observer that formats events to a flattened JSON representation.

    Args:
        hs (HomeServer): The homeserver that is being logged for.
        host: The host of the logging target.
        port: The logging target's port.
        metadata: Metadata to be added to each log object.
        maximum_buffer: The maximum buffer size.
    """

    def formatEvent(_event: dict) -> str:
        flattened = flatten_event(_event, metadata, include_time=True)
        return _encoder.encode(flattened) + "\n"

    return TCPLogObserver(hs, host, port, formatEvent, maximum_buffer)
