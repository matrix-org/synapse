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

import json
from collections import Counter

from twisted.logger import Logger

from synapse.logging._structured import setup_structured_logging

from tests.server import connect_client
from tests.unittest import HomeserverTestCase

from .test_structured import FakeBeginner, StructuredLoggingTestBase


class TerseJSONTCPTestCase(StructuredLoggingTestBase, HomeserverTestCase):
    def test_log_output(self):
        """
        The Terse JSON outputter delivers simplified structured logs over TCP.
        """
        log_config = {
            "drains": {
                "tersejson": {
                    "type": "network_json_terse",
                    "host": "127.0.0.1",
                    "port": 8000,
                }
            }
        }

        # Begin the logger with our config
        beginner = FakeBeginner()
        setup_structured_logging(
            self.hs, self.hs.config, log_config, logBeginner=beginner
        )

        logger = Logger(
            namespace="tests.logging.test_terse_json", observer=beginner.observers[0]
        )
        logger.info("Hello there, {name}!", name="wally")

        # Trigger the connection
        self.pump()

        _, server = connect_client(self.reactor, 0)

        # Trigger data being sent
        self.pump()

        # One log message, with a single trailing newline
        logs = server.data.decode("utf8").splitlines()
        self.assertEqual(len(logs), 1)
        self.assertEqual(server.data.count(b"\n"), 1)

        log = json.loads(logs[0])

        # The terse logger should give us these keys.
        expected_log_keys = [
            "log",
            "time",
            "level",
            "log_namespace",
            "request",
            "scope",
            "server_name",
            "name",
        ]
        self.assertEqual(set(log.keys()), set(expected_log_keys))

        # It contains the data we expect.
        self.assertEqual(log["name"], "wally")

    def test_log_backpressure_debug(self):
        """
        When backpressure is hit, DEBUG logs will be shed.
        """
        log_config = {
            "loggers": {"synapse": {"level": "DEBUG"}},
            "drains": {
                "tersejson": {
                    "type": "network_json_terse",
                    "host": "127.0.0.1",
                    "port": 8000,
                    "maximum_buffer": 10,
                }
            },
        }

        # Begin the logger with our config
        beginner = FakeBeginner()
        setup_structured_logging(
            self.hs,
            self.hs.config,
            log_config,
            logBeginner=beginner,
            redirect_stdlib_logging=False,
        )

        logger = Logger(
            namespace="synapse.logging.test_terse_json", observer=beginner.observers[0]
        )

        # Send some debug messages
        for i in range(0, 3):
            logger.debug("debug %s" % (i,))

        # Send a bunch of useful messages
        for i in range(0, 7):
            logger.info("test message %s" % (i,))

        # The last debug message pushes it past the maximum buffer
        logger.debug("too much debug")

        # Allow the reconnection
        _, server = connect_client(self.reactor, 0)
        self.pump()

        # Only the 7 infos made it through, the debugs were elided
        logs = server.data.splitlines()
        self.assertEqual(len(logs), 7)

    def test_log_backpressure_info(self):
        """
        When backpressure is hit, DEBUG and INFO logs will be shed.
        """
        log_config = {
            "loggers": {"synapse": {"level": "DEBUG"}},
            "drains": {
                "tersejson": {
                    "type": "network_json_terse",
                    "host": "127.0.0.1",
                    "port": 8000,
                    "maximum_buffer": 10,
                }
            },
        }

        # Begin the logger with our config
        beginner = FakeBeginner()
        setup_structured_logging(
            self.hs,
            self.hs.config,
            log_config,
            logBeginner=beginner,
            redirect_stdlib_logging=False,
        )

        logger = Logger(
            namespace="synapse.logging.test_terse_json", observer=beginner.observers[0]
        )

        # Send some debug messages
        for i in range(0, 3):
            logger.debug("debug %s" % (i,))

        # Send a bunch of useful messages
        for i in range(0, 10):
            logger.warn("test warn %s" % (i,))

        # Send a bunch of info messages
        for i in range(0, 3):
            logger.info("test message %s" % (i,))

        # The last debug message pushes it past the maximum buffer
        logger.debug("too much debug")

        # Allow the reconnection
        client, server = connect_client(self.reactor, 0)
        self.pump()

        # The 10 warnings made it through, the debugs and infos were elided
        logs = list(map(json.loads, server.data.decode("utf8").splitlines()))
        self.assertEqual(len(logs), 10)

        self.assertEqual(Counter([x["level"] for x in logs]), {"WARN": 10})

    def test_log_backpressure_cut_middle(self):
        """
        When backpressure is hit, and no more DEBUG and INFOs cannot be culled,
        it will cut the middle messages out.
        """
        log_config = {
            "loggers": {"synapse": {"level": "DEBUG"}},
            "drains": {
                "tersejson": {
                    "type": "network_json_terse",
                    "host": "127.0.0.1",
                    "port": 8000,
                    "maximum_buffer": 10,
                }
            },
        }

        # Begin the logger with our config
        beginner = FakeBeginner()
        setup_structured_logging(
            self.hs,
            self.hs.config,
            log_config,
            logBeginner=beginner,
            redirect_stdlib_logging=False,
        )

        logger = Logger(
            namespace="synapse.logging.test_terse_json", observer=beginner.observers[0]
        )

        # Send a bunch of useful messages
        for i in range(0, 20):
            logger.warn("test warn", num=i)

        # Allow the reconnection
        client, server = connect_client(self.reactor, 0)
        self.pump()

        # The first five and last five warnings made it through, the debugs and
        # infos were elided
        logs = list(map(json.loads, server.data.decode("utf8").splitlines()))
        self.assertEqual(len(logs), 10)
        self.assertEqual(Counter([x["level"] for x in logs]), {"WARN": 10})
        self.assertEqual([0, 1, 2, 3, 4, 15, 16, 17, 18, 19], [x["num"] for x in logs])
