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

import sys
import traceback
from collections import deque
from ipaddress import IPv4Address, IPv6Address, ip_address
from math import floor
from typing import Callable, Optional

import attr
from zope.interface import implementer

from twisted.application.internet import ClientService
from twisted.internet.defer import Deferred
from twisted.internet.endpoints import (
    HostnameEndpoint,
    TCP4ClientEndpoint,
    TCP6ClientEndpoint,
)
from twisted.internet.interfaces import IPushProducer, ITransport
from twisted.internet.protocol import Factory, Protocol
from twisted.logger import ILogObserver, Logger, LogLevel


@attr.s
@implementer(IPushProducer)
class LogProducer:
    """
    An IPushProducer that writes logs from its buffer to its transport when it
    is resumed.

    Args:
        buffer: Log buffer to read logs from.
        transport: Transport to write to.
        format_event: A callable to format the log entry to a string.
    """

    transport = attr.ib(type=ITransport)
    format_event = attr.ib(type=Callable[[dict], str])
    _buffer = attr.ib(type=deque)
    _paused = attr.ib(default=False, type=bool, init=False)

    def pauseProducing(self):
        self._paused = True

    def stopProducing(self):
        self._paused = True
        self._buffer = deque()

    def resumeProducing(self):
        self._paused = False

        while self._paused is False and (self._buffer and self.transport.connected):
            try:
                # Request the next event and format it.
                event = self._buffer.popleft()
                msg = self.format_event(event)

                # Send it as a new line over the transport.
                self.transport.write(msg.encode("utf8"))
            except Exception:
                # Something has gone wrong writing to the transport -- log it
                # and break out of the while.
                traceback.print_exc(file=sys.__stderr__)
                break


@attr.s
@implementer(ILogObserver)
class TCPLogObserver:
    """
    An IObserver that writes JSON logs to a TCP target.

    Args:
        hs (HomeServer): The homeserver that is being logged for.
        host: The host of the logging target.
        port: The logging target's port.
        format_event: A callable to format the log entry to a string.
        maximum_buffer: The maximum buffer size.
    """

    hs = attr.ib()
    host = attr.ib(type=str)
    port = attr.ib(type=int)
    format_event = attr.ib(type=Callable[[dict], str])
    maximum_buffer = attr.ib(type=int)
    _buffer = attr.ib(default=attr.Factory(deque), type=deque)
    _connection_waiter = attr.ib(default=None, type=Optional[Deferred])
    _logger = attr.ib(default=attr.Factory(Logger))
    _producer = attr.ib(default=None, type=Optional[LogProducer])

    def start(self) -> None:

        # Connect without DNS lookups if it's a direct IP.
        try:
            ip = ip_address(self.host)
            if isinstance(ip, IPv4Address):
                endpoint = TCP4ClientEndpoint(
                    self.hs.get_reactor(), self.host, self.port
                )
            elif isinstance(ip, IPv6Address):
                endpoint = TCP6ClientEndpoint(
                    self.hs.get_reactor(), self.host, self.port
                )
            else:
                raise ValueError("Unknown IP address provided: %s" % (self.host,))
        except ValueError:
            endpoint = HostnameEndpoint(self.hs.get_reactor(), self.host, self.port)

        factory = Factory.forProtocol(Protocol)
        self._service = ClientService(endpoint, factory, clock=self.hs.get_reactor())
        self._service.startService()
        self._connect()

    def stop(self):
        self._service.stopService()

    def _connect(self) -> None:
        """
        Triggers an attempt to connect then write to the remote if not already writing.
        """
        if self._connection_waiter:
            return

        self._connection_waiter = self._service.whenConnected(failAfterFailures=1)

        @self._connection_waiter.addErrback
        def fail(r):
            r.printTraceback(file=sys.__stderr__)
            self._connection_waiter = None
            self._connect()

        @self._connection_waiter.addCallback
        def writer(r):
            # We have a connection. If we already have a producer, and its
            # transport is the same, just trigger a resumeProducing.
            if self._producer and r.transport is self._producer.transport:
                self._producer.resumeProducing()
                self._connection_waiter = None
                return

            # If the producer is still producing, stop it.
            if self._producer:
                self._producer.stopProducing()

            # Make a new producer and start it.
            self._producer = LogProducer(
                buffer=self._buffer,
                transport=r.transport,
                format_event=self.format_event,
            )
            r.transport.registerProducer(self._producer, True)
            self._producer.resumeProducing()
            self._connection_waiter = None

    def _handle_pressure(self) -> None:
        """
        Handle backpressure by shedding events.

        The buffer will, in this order, until the buffer is below the maximum:
            - Shed DEBUG events
            - Shed INFO events
            - Shed the middle 50% of the events.
        """
        if len(self._buffer) <= self.maximum_buffer:
            return

        # Strip out DEBUGs
        self._buffer = deque(
            filter(lambda event: event["log_level"] != LogLevel.debug, self._buffer)
        )

        if len(self._buffer) <= self.maximum_buffer:
            return

        # Strip out INFOs
        self._buffer = deque(
            filter(lambda event: event["log_level"] != LogLevel.info, self._buffer)
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

    def __call__(self, event: dict) -> None:
        self._buffer.append(event)

        # Handle backpressure, if it exists.
        try:
            self._handle_pressure()
        except Exception:
            # If handling backpressure fails,clear the buffer and log the
            # exception.
            self._buffer.clear()
            self._logger.failure("Failed clearing backpressure")

        # Try and write immediately.
        self._connect()
