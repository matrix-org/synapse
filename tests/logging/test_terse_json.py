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

from twisted.logger import Logger

from synapse.logging._structured import setup_structured_logging

from tests.server import connect_client
from tests.unittest import HomeserverTestCase

from .test_structured import FakeBeginner


class TerseJSONTCPTestCase(HomeserverTestCase):
    def test_write_loop(self):
        """
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

        server = connect_client(self.reactor, self.reactor.tcpClients[0][2])

        # Trigger data being sent
        self.pump()

        # One log message, with a single trailing newline
        logs = b"\n".split(server.data)
        self.assertEqual(len(logs), 1)
        self.assertEqual(server.data.count(b"\n"))

        log = json.loads(logs[0])

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

        print(server.data)
