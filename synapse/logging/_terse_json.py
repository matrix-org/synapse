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

import sys
from collections import deque
from typing import TextIO

import attr
from simplejson import dumps

from twisted.application.internet import ClientService
from twisted.internet.endpoints import HostnameEndpoint
from twisted.internet.protocol import Factory, Protocol
from twisted.logger import FileLogObserver
from twisted.python.failure import Failure


def flatten_event(_event: dict, metadata: dict, include_time: bool = False):
    """
    Flatten a Twisted logging event to an dictionary capable of being sent
    as a log event to a logging aggregation system.

    The format is vastly simplified and is not designed to be a "human readable
    string" in the sense that traditional logs are. Instead, the structure is
    optimised for searchability and filtering, with human-understandable log
    keys.

    Args:
        _event (dict): The Twisted logging event we are flattening.
        metadata (dict): Additional data to include with each log message. This
            can be information like the server name. Since the target log
            consumer does not know who we are other than by host IP, this
            allows us to forward through static information.
        include_time (bool): Should we include the `time` key? If False, the
            event time is stripped from the event.
    """
    event = {}

    # If it's a failure, make the new event's log_failure be the traceback text.
    if "log_failure" in _event:
        event["log_failure"] = _event["log_failure"].getTraceback()

    # If it's a warning, copy over a string representation of the warning.
    if "warning" in _event:
        event["warning"] = str(_event["warning"])

    # Stdlib logging events have "log_text" as their human-readable portion,
    # Twisted ones have "log_format". For now, include the log_format, so that
    # context only given in the log format (e.g. what is being logged) is
    # available.
    if "log_text" in _event:
        event["log"] = _event["log_text"]
    else:
        event["log"] = _event["log_format"]

    # We want to include the timestamp when forwarding over the network, but
    # exclude it when we are writing to stdout. This is because the log ingester
    # (e.g. logstash, fluentd) can add its own timestamp.
    if include_time:
        event["time"] = _event["log_time"]

    # Convert the log level to a textual representation.
    event["level"] = _event["log_level"].name.upper()

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
    if _event.get("log_namespace") == "log_legacy":
        keys_to_delete.extend(["message", "system", "time"])

    # Rather than modify the dictionary in place, construct a new one with only
    # the content we want. The original event should be considered 'frozen'.
    for key in _event.keys():

        if key in keys_to_delete:
            continue

        if isinstance(_event[key], (str, int, bool, float)) or _event[key] is None:
            # If it's a plain type, include it as is.
            event[key] = _event[key]
        else:
            # If it's not one of those basic types, write out a string
            # representation. This should probably be a warning in development,
            # so that we are sure we are only outputting useful data.
            event[key] = str(_event[key])

    # Add the metadata information to the event (e.g. the server_name).
    event.update(metadata)

    return event


def TerseJSONToConsoleLogObserver(outFile: TextIO, metadata: dict) -> FileLogObserver:
    """
    A log observer that formats events to a flattened JSON representation.

    Args:
        outFile: The file object to write to.
        metadata: Metadata to be added to each log object.
    """

    def formatEvent(_event: dict) -> str:
        flattened = flatten_event(_event, metadata)
        return dumps(flattened, ensure_ascii=False, separators=(",", ":")) + "\n"

    return FileLogObserver(outFile, formatEvent)


@attr.s
class TerseJSONToTCPLogObserver(object):
    """
    An IObserver that writes JSON logs to a TCP target.

    Args:
        hs (HomeServer): The Homeserver that is being logged for.
        host: The host of the logging target.
        port: The logging target's port.
        metadata: Metadata to be added to each log entry.
    """

    hs = attr.ib()
    host = attr.ib(type=str)
    port = attr.ib(type=int)
    metadata = attr.ib(type=dict)
    _buffer = attr.ib(default=attr.Factory(deque), type=deque)
    _writer = attr.ib(default=None)

    def start(self) -> None:
        endpoint = HostnameEndpoint(self.hs.get_reactor(), self.host, self.port)
        factory = Factory.forProtocol(Protocol)
        self._service = ClientService(endpoint, factory)
        self._service.startService()

    def _write_loop(self) -> None:
        """
        Implement the write loop.
        """
        if self._writer:
            return

        self._writer = self._service.whenConnected()

        @self._writer.addBoth
        def _(r):
            if isinstance(r, Failure):
                r.printTraceback(file=sys.__stderr__)
                self._writer = None
                self.hs.get_reactor().callLater(1, self._write_loop)
                return

            try:
                r.transport.write(b"\n".join(reversed(self._buffer)) + b"\n")
                self._buffer.clear()
            except Exception as e:
                sys.__stderr__.write("Failed writing out logs with %s\n" % (str(e),))

            self._writer = False
            self.hs.get_reactor().callLater(1, self._write_loop)

    def __call__(self, _event: dict) -> None:
        flattened = flatten_event(_event, self.metadata, include_time=True)
        self._buffer.append(
            dumps(flattened, ensure_ascii=False, separators=(",", ":")).encode("utf8")
        )
        # Try and write immediately
        self._write_loop()
