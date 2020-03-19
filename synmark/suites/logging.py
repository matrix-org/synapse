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

import warnings
from io import StringIO

from mock import Mock

from pyperf import perf_counter
from synmark import make_homeserver

from twisted.internet.defer import Deferred
from twisted.internet.protocol import ServerFactory
from twisted.logger import LogBeginner, Logger, LogPublisher
from twisted.protocols.basic import LineOnlyReceiver

from synapse.logging._structured import setup_structured_logging


class LineCounter(LineOnlyReceiver):

    delimiter = b"\n"

    def __init__(self, *args, **kwargs):
        self.count = 0
        super().__init__(*args, **kwargs)

    def lineReceived(self, line):
        self.count += 1

        if self.count >= self.factory.wait_for and self.factory.on_done:
            on_done = self.factory.on_done
            self.factory.on_done = None
            on_done.callback(True)


async def main(reactor, loops):
    """
    Benchmark how long it takes to send `loops` messages.
    """
    servers = []

    def protocol():
        p = LineCounter()
        servers.append(p)
        return p

    logger_factory = ServerFactory.forProtocol(protocol)
    logger_factory.wait_for = loops
    logger_factory.on_done = Deferred()
    port = reactor.listenTCP(0, logger_factory, interface="127.0.0.1")

    hs, wait, cleanup = await make_homeserver(reactor)

    errors = StringIO()
    publisher = LogPublisher()
    mock_sys = Mock()
    beginner = LogBeginner(
        publisher, errors, mock_sys, warnings, initialBufferSize=loops
    )

    log_config = {
        "loggers": {"synapse": {"level": "DEBUG"}},
        "drains": {
            "tersejson": {
                "type": "network_json_terse",
                "host": "127.0.0.1",
                "port": port.getHost().port,
                "maximum_buffer": 100,
            }
        },
    }

    logger = Logger(namespace="synapse.logging.test_terse_json", observer=publisher)
    logging_system = setup_structured_logging(
        hs, hs.config, log_config, logBeginner=beginner, redirect_stdlib_logging=False
    )

    # Wait for it to connect...
    await logging_system._observers[0]._service.whenConnected()

    start = perf_counter()

    # Send a bunch of useful messages
    for i in range(0, loops):
        logger.info("test message %s" % (i,))

        if (
            len(logging_system._observers[0]._buffer)
            == logging_system._observers[0].maximum_buffer
        ):
            while (
                len(logging_system._observers[0]._buffer)
                > logging_system._observers[0].maximum_buffer / 2
            ):
                await wait(0.01)

    await logger_factory.on_done

    end = perf_counter() - start

    logging_system.stop()
    port.stopListening()
    cleanup()

    return end
