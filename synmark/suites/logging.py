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
import logging.config
import warnings
from io import StringIO
from typing import Optional
from unittest.mock import Mock

from pyperf import perf_counter

from twisted.internet.address import IPv4Address, IPv6Address
from twisted.internet.defer import Deferred
from twisted.internet.protocol import ServerFactory
from twisted.logger import LogBeginner, LogPublisher
from twisted.protocols.basic import LineOnlyReceiver

from synapse.config.logger import _setup_stdlib_logging
from synapse.logging import RemoteHandler
from synapse.synapse_rust import reset_logging_config
from synapse.types import ISynapseReactor
from synapse.util import Clock


class LineCounter(LineOnlyReceiver):
    delimiter = b"\n"
    count = 0

    def lineReceived(self, line: bytes) -> None:
        self.count += 1

        assert isinstance(self.factory, Factory)

        if self.count >= self.factory.wait_for and self.factory.on_done:
            on_done = self.factory.on_done
            self.factory.on_done = None
            on_done.callback(True)


class Factory(ServerFactory):
    protocol = LineCounter
    wait_for: int
    on_done: Optional[Deferred]


async def main(reactor: ISynapseReactor, loops: int) -> float:
    """
    Benchmark how long it takes to send `loops` messages.
    """

    logger_factory = Factory()
    logger_factory.wait_for = loops
    logger_factory.on_done = Deferred()
    port = reactor.listenTCP(0, logger_factory, backlog=50, interface="127.0.0.1")

    # A fake homeserver config.
    class Config:
        class server:
            server_name = "synmark-" + str(loops)

        # This odd construct is to avoid mypy thinking that logging escapes the
        # scope of Config.
        class _logging:
            no_redirect_stdio = True

        logging = _logging

    hs_config = Config()

    # To be able to sleep.
    clock = Clock(reactor)

    errors = StringIO()
    publisher = LogPublisher()
    mock_sys = Mock()
    beginner = LogBeginner(
        publisher, errors, mock_sys, warnings, initialBufferSize=loops
    )

    address = port.getHost()
    assert isinstance(address, (IPv4Address, IPv6Address))
    log_config = {
        "version": 1,
        "loggers": {"synapse": {"level": "DEBUG", "handlers": ["remote"]}},
        "formatters": {"tersejson": {"class": "synapse.logging.TerseJsonFormatter"}},
        "handlers": {
            "remote": {
                "class": "synapse.logging.RemoteHandler",
                "formatter": "tersejson",
                "host": address.host,
                "port": address.port,
                "maximum_buffer": 100,
            }
        },
    }

    logger = logging.getLogger("synapse")
    _setup_stdlib_logging(
        hs_config,  # type: ignore[arg-type]
        None,
        logBeginner=beginner,
    )

    # Force a new logging config without having to load it from a file.
    logging.config.dictConfig(log_config)
    reset_logging_config()

    # Wait for it to connect...
    for handler in logging.getLogger("synapse").handlers:
        if isinstance(handler, RemoteHandler):
            break
    else:
        raise RuntimeError("Improperly configured: no RemoteHandler found.")

    await handler._service.whenConnected(failAfterFailures=10)

    start = perf_counter()

    # Send a bunch of useful messages
    for i in range(loops):
        logger.info("test message %s", i)

        if len(handler._buffer) == handler.maximum_buffer:
            while len(handler._buffer) > handler.maximum_buffer / 2:
                await clock.sleep(0.01)

    await logger_factory.on_done

    end = perf_counter() - start

    handler.close()
    port.stopListening()

    return end
