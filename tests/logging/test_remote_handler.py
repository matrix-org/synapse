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
from typing import Tuple

from twisted.internet.protocol import Protocol
from twisted.test.proto_helpers import AccumulatingProtocol, MemoryReactorClock

from synapse.logging import RemoteHandler

from tests.logging import LoggerCleanupMixin
from tests.server import FakeTransport, get_clock
from tests.unittest import TestCase
from tests.utils import checked_cast


def connect_logging_client(
    reactor: MemoryReactorClock, client_id: int
) -> Tuple[Protocol, AccumulatingProtocol]:
    # This is essentially tests.server.connect_client, but disabling autoflush on
    # the client transport. This is necessary to avoid an infinite loop due to
    # sending of data via the logging transport causing additional logs to be
    # written.
    factory = reactor.tcpClients.pop(client_id)[2]
    client = factory.buildProtocol(None)
    server = AccumulatingProtocol()
    server.makeConnection(FakeTransport(client, reactor))
    client.makeConnection(FakeTransport(server, reactor, autoflush=False))

    return client, server


class RemoteHandlerTestCase(LoggerCleanupMixin, TestCase):
    def setUp(self) -> None:
        self.reactor, _ = get_clock()

    def test_log_output(self) -> None:
        """
        The remote handler delivers logs over TCP.
        """
        handler = RemoteHandler("127.0.0.1", 9000, _reactor=self.reactor)
        logger = self.get_logger(handler)

        logger.info("Hello there, %s!", "wally")

        # Trigger the connection
        client, server = connect_logging_client(self.reactor, 0)

        # Trigger data being sent
        client_transport = checked_cast(FakeTransport, client.transport)
        client_transport.flush()

        # One log message, with a single trailing newline
        logs = server.data.decode("utf8").splitlines()
        self.assertEqual(len(logs), 1)
        self.assertEqual(server.data.count(b"\n"), 1)

        # Ensure the data passed through properly.
        self.assertEqual(logs[0], "Hello there, wally!")

    def test_log_backpressure_debug(self) -> None:
        """
        When backpressure is hit, DEBUG logs will be shed.
        """
        handler = RemoteHandler(
            "127.0.0.1", 9000, maximum_buffer=10, _reactor=self.reactor
        )
        logger = self.get_logger(handler)

        # Send some debug messages
        for i in range(3):
            logger.debug("debug %s" % (i,))

        # Send a bunch of useful messages
        for i in range(7):
            logger.info("info %s" % (i,))

        # The last debug message pushes it past the maximum buffer
        logger.debug("too much debug")

        # Allow the reconnection
        client, server = connect_logging_client(self.reactor, 0)
        client_transport = checked_cast(FakeTransport, client.transport)
        client_transport.flush()

        # Only the 7 infos made it through, the debugs were elided
        logs = server.data.splitlines()
        self.assertEqual(len(logs), 7)
        self.assertNotIn(b"debug", server.data)

    def test_log_backpressure_info(self) -> None:
        """
        When backpressure is hit, DEBUG and INFO logs will be shed.
        """
        handler = RemoteHandler(
            "127.0.0.1", 9000, maximum_buffer=10, _reactor=self.reactor
        )
        logger = self.get_logger(handler)

        # Send some debug messages
        for i in range(3):
            logger.debug("debug %s" % (i,))

        # Send a bunch of useful messages
        for i in range(10):
            logger.warning("warn %s" % (i,))

        # Send a bunch of info messages
        for i in range(3):
            logger.info("info %s" % (i,))

        # The last debug message pushes it past the maximum buffer
        logger.debug("too much debug")

        # Allow the reconnection
        client, server = connect_logging_client(self.reactor, 0)
        client_transport = checked_cast(FakeTransport, client.transport)
        client_transport.flush()

        # The 10 warnings made it through, the debugs and infos were elided
        logs = server.data.splitlines()
        self.assertEqual(len(logs), 10)
        self.assertNotIn(b"debug", server.data)
        self.assertNotIn(b"info", server.data)

    def test_log_backpressure_cut_middle(self) -> None:
        """
        When backpressure is hit, and no more DEBUG and INFOs cannot be culled,
        it will cut the middle messages out.
        """
        handler = RemoteHandler(
            "127.0.0.1", 9000, maximum_buffer=10, _reactor=self.reactor
        )
        logger = self.get_logger(handler)

        # Send a bunch of useful messages
        for i in range(20):
            logger.warning("warn %s" % (i,))

        # Allow the reconnection
        client, server = connect_logging_client(self.reactor, 0)
        client_transport = checked_cast(FakeTransport, client.transport)
        client_transport.flush()

        # The first five and last five warnings made it through, the debugs and
        # infos were elided
        logs = server.data.decode("utf8").splitlines()
        self.assertEqual(
            ["warn %s" % (i,) for i in range(5)]
            + ["warn %s" % (i,) for i in range(15, 20)],
            logs,
        )

    def test_cancel_connection(self) -> None:
        """
        Gracefully handle the connection being cancelled.
        """
        handler = RemoteHandler(
            "127.0.0.1", 9000, maximum_buffer=10, _reactor=self.reactor
        )
        logger = self.get_logger(handler)

        # Send a message.
        logger.info("Hello there, %s!", "wally")

        # Do not accept the connection and shutdown. This causes the pending
        # connection to be cancelled (and should not raise any exceptions).
        handler.close()
