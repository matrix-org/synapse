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

import attr
from simplejson import dumps

from twisted.application.internet import ClientService
from twisted.internet.endpoints import HostnameEndpoint
from twisted.internet.protocol import Factory, Protocol
from twisted.logger import FileLogObserver
from twisted.python.failure import Failure


def flatten_event(_event, metadata, include_time=False):
    """
    Flatten a Twisted logging event to something that makes more sense to go
    into a structured logging aggregation system.

    The format is vastly simplified and
    """
    event = {}

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

    if _event.get("log_namespace") == "log_legacy":
        keys_to_delete.extend(["message", "system", "time"])

    if "log_failure" in _event:
        event["log_failure"] = _event["log_failure"].getTraceback()

    if "warning" in _event:
        event["warning"] = str(_event["warning"])

    if "log_text" in _event:
        event["log"] = _event["log_text"]
    else:
        event["log"] = _event["log_format"]

    if include_time:
        event["time"] = _event["log_time"]

    event["level"] = _event["log_level"].name

    for key in _event.keys():

        if key in keys_to_delete:
            continue

        if isinstance(_event[key], (str, int, bool, float)) or _event[key] is None:
            event[key] = _event[key]
        else:
            event[key] = str(_event[key])

    return {**event, **metadata}


def TerseJSONToConsoleLogObserver(outFile, metadata={}):
    """
    A log observer that formats events to a flattened JSON representation.

    Args:
        outFile (file object): The file object to write to.
        metadata (dict): Metadata to be added to the log file.
    """

    def formatEvent(_event):
        flattened = flatten_event(_event, metadata)
        return dumps(flattened, ensure_ascii=False, separators=(",", ":")) + "\n"

    return FileLogObserver(outFile, formatEvent)


@attr.s
class TerseJSONToTCPLogObserver(object):

    hs = attr.ib()
    host = attr.ib()
    port = attr.ib()
    metadata = attr.ib()
    retry_time = attr.ib(default=5)
    _buffer = attr.ib(default=attr.Factory(deque))
    _writer = attr.ib(default=None)

    def start(self):
        endpoint = HostnameEndpoint(self.hs.get_reactor(), self.host, self.port)
        factory = Factory.forProtocol(Protocol)
        self._service = ClientService(endpoint, factory)
        self._service.startService()

    def _write_loop(self):
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
                self.hs.get_reactor().callLater(self.retry_time, self._write_loop)
                return

            try:
                r.transport.write(b"\n".join(reversed(self._buffer)) + b"\n")
                self._buffer.clear()
            except Exception as e:
                sys.__stderr__.write("Failed writing out logs with %s\n" % (str(e),))

            self._writer = False
            self.hs.get_reactor().callLater(self.retry_time, self._write_loop)

    def __call__(self, _event):
        flattened = flatten_event(_event, self.metadata, include_time=True)
        self._buffer.append(
            dumps(flattened, ensure_ascii=False, separators=(",", ":")).encode("utf8")
        )
        # Try and write immediately
        self._write_loop()
