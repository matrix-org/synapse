# -*- coding: utf-8 -*-
# Copyright 2020 The Matrix.org Foundation C.I.C.
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
import traceback
from collections import deque
from ipaddress import IPv4Address, IPv6Address, ip_address
from math import floor
from typing import Callable, Optional

import attr
from typing_extensions import Deque
from zope.interface import implementer

from twisted.application.internet import ClientService
from twisted.internet.defer import CancelledError, Deferred
from twisted.internet.endpoints import (
    HostnameEndpoint,
    TCP4ClientEndpoint,
    TCP6ClientEndpoint,
)
from twisted.internet.interfaces import IPushProducer, IStreamClientEndpoint
from twisted.internet.protocol import Factory, Protocol
from twisted.internet.tcp import Connection
from twisted.python.failure import Failure

logger = logging.getLogger(__name__)


@attr.s
@implementer(IPushProducer)
class LogProducer:
    """
    An IPushProducer that writes logs from its buffer to its transport when it
    is resumed.

    Args:
        buffer: Log buffer to read logs from.
        transport: Transport to write to.
        format: A callable to format the log record to a string.
    """

    # This is essentially ITCPTransport, but that is missing certain fields
    # (connected and registerProducer) which are part of the implementation.
    transport = attr.ib(type=Connection)
    _format = attr.ib(type=Callable[[logging.LogRecord], str])
    _buffer = attr.ib(type=deque)
    _paused = attr.ib(default=False, type=bool, init=False)

    def pauseProducing(self):
        self._paused = True

    def stopProducing(self):
        self._paused = True
        self._buffer = deque()

    def resumeProducing(self):
        # If we're already producing, nothing to do.
        self._paused = False

        # Loop until paused.
        while self._paused is False and (self._buffer and self.transport.connected):
            try:
                # Request the next record and format it.
                record = self._buffer.popleft()
                msg = self._format(record)

                # Send it as a new line over the transport.
                self.transport.write(msg.encode("utf8"))
                self.transport.write(b"\n")
            except Exception:
                # Something has gone wrong writing to the transport -- log it
                # and break out of the while.
                traceback.print_exc(file=sys.__stderr__)
                break


class RemoteHandler(logging.Handler):
    """
    An logging handler that writes logs to a TCP target.

    Args:
        host: The host of the logging target.
        port: The logging target's port.
        maximum_buffer: The maximum buffer size.
    """

    def __init__(
        self,
        host: str,
        port: int,
        maximum_buffer: int = 1000,
        level=logging.NOTSET,
        _reactor=None,
    ):
        super().__init__(level=level)
        self.host = host
        self.port = port
        self.maximum_buffer = maximum_buffer

        self._buffer = deque()  # type: Deque[logging.LogRecord]
        self._connection_waiter = None  # type: Optional[Deferred]
        self._producer = None  # type: Optional[LogProducer]

        # Connect without DNS lookups if it's a direct IP.
        if _reactor is None:
            from twisted.internet import reactor

            _reactor = reactor

        try:
            ip = ip_address(self.host)
            if isinstance(ip, IPv4Address):
                endpoint = TCP4ClientEndpoint(
                    _reactor, self.host, self.port
                )  # type: IStreamClientEndpoint
            elif isinstance(ip, IPv6Address):
                endpoint = TCP6ClientEndpoint(_reactor, self.host, self.port)
            else:
                raise ValueError("Unknown IP address provided: %s" % (self.host,))
        except ValueError:
            endpoint = HostnameEndpoint(_reactor, self.host, self.port)

        factory = Factory.forProtocol(Protocol)
        self._service = ClientService(endpoint, factory, clock=_reactor)
        self._service.startService()
        self._stopping = False
        self._connect()

    def close(self):
        self._stopping = True
        self._service.stopService()

    def _connect(self) -> None:
        """
        Triggers an attempt to connect then write to the remote if not already writing.
        """
        # Do not attempt to open multiple connections.
        if self._connection_waiter:
            return

        def fail(failure: Failure) -> None:
            # If the Deferred was cancelled (e.g. during shutdown) do not try to
            # reconnect (this will cause an infinite loop of errors).
            if failure.check(CancelledError) and self._stopping:
                return

            # For a different error, print the traceback and re-connect.
            failure.printTraceback(file=sys.__stderr__)
            self._connection_waiter = None
            self._connect()

        def writer(result: Protocol) -> None:
            # Force recognising transport as a Connection and not the more
            # generic ITransport.
            transport = result.transport  # type: Connection  # type: ignore

            # We have a connection. If we already have a producer, and its
            # transport is the same, just trigger a resumeProducing.
            if self._producer and transport is self._producer.transport:
                self._producer.resumeProducing()
                self._connection_waiter = None
                return

            # If the producer is still producing, stop it.
            if self._producer:
                self._producer.stopProducing()

            # Make a new producer and start it.
            self._producer = LogProducer(
                buffer=self._buffer,
                transport=transport,
                format=self.format,
            )
            transport.registerProducer(self._producer, True)
            self._producer.resumeProducing()
            self._connection_waiter = None

        deferred = self._service.whenConnected(failAfterFailures=1)  # type: Deferred
        deferred.addCallbacks(writer, fail)
        self._connection_waiter = deferred

    def _handle_pressure(self) -> None:
        """
        Handle backpressure by shedding records.

        The buffer will, in this order, until the buffer is below the maximum:
            - Shed DEBUG records.
            - Shed INFO records.
            - Shed the middle 50% of the records.
        """
        if len(self._buffer) <= self.maximum_buffer:
            return

        # Strip out DEBUGs
        self._buffer = deque(
            filter(lambda record: record.levelno > logging.DEBUG, self._buffer)
        )

        if len(self._buffer) <= self.maximum_buffer:
            return

        # Strip out INFOs
        self._buffer = deque(
            filter(lambda record: record.levelno > logging.INFO, self._buffer)
        )

        if len(self._buffer) <= self.maximum_buffer:
            return

        # Cut the middle entries out
        buffer_split = floor(self.maximum_buffer / 2)

        old_buffer = self._buffer
        self._buffer = deque()

        for i in range(buffer_split):
            self._buffer.append(old_buffer.popleft())

        end_buffer = []
        for i in range(buffer_split):
            end_buffer.append(old_buffer.pop())

        self._buffer.extend(reversed(end_buffer))

    def emit(self, record: logging.LogRecord) -> None:
        self._buffer.append(record)

        # Handle backpressure, if it exists.
        try:
            self._handle_pressure()
        except Exception:
            # If handling backpressure fails, clear the buffer and log the
            # exception.
            self._buffer.clear()
            logger.warning("Failed clearing backpressure")

        # Try and write immediately.
        self._connect()
