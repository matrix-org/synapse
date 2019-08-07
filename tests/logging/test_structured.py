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

import os
import os.path
import shutil

from twisted.logger import Logger, eventAsText, eventsFromJSONLogFile

from synapse.logging._structured import setup_structured_logging
from synapse.logging.context import LoggingContext

from tests.unittest import HomeserverTestCase


class FakeBeginner(object):
    def beginLoggingTo(self, observers, **kwargs):
        self.observers = observers


class StructuredLoggingTestCase(HomeserverTestCase):
    """
    Tests for Synapse's structured logging support.
    """

    def test_output_to_json_round_trip(self):
        """
        Synapse logs can be outputted to JSON and then read back again.
        """
        temp_dir = self.mktemp()
        os.mkdir(temp_dir)
        self.addCleanup(shutil.rmtree, temp_dir)

        json_log_file = os.path.join(temp_dir, "out.json")

        log_config = {
            "drains": {"jsonfile": {"type": "file_json", "location": json_log_file}}
        }

        # Begin the logger with our config
        beginner = FakeBeginner()
        setup_structured_logging(self.hs.config, log_config, logBeginner=beginner)

        # Make a logger and send an event
        logger = Logger(
            namespace="tests.logging.test_structured", observer=beginner.observers[0]
        )
        logger.info("Hello there, {name}!", name="wally")

        # Read the log file and check it has the event we sent
        with open(json_log_file, "r") as f:
            logged_events = list(eventsFromJSONLogFile(f))
        self.assertEqual(len(logged_events), 1)

        # The event pulled from the file should render fine
        self.assertEqual(
            eventAsText(logged_events[0], includeTimestamp=False),
            "[tests.logging.test_structured#info] Hello there, wally!",
        )

    def test_output_to_text(self):
        """
        Synapse logs can be outputted to text.
        """
        temp_dir = self.mktemp()
        os.mkdir(temp_dir)
        self.addCleanup(shutil.rmtree, temp_dir)

        log_file = os.path.join(temp_dir, "out.log")

        log_config = {"drains": {"file": {"type": "file", "location": log_file}}}

        # Begin the logger with our config
        beginner = FakeBeginner()
        setup_structured_logging(self.hs.config, log_config, logBeginner=beginner)

        # Make a logger and send an event
        logger = Logger(
            namespace="tests.logging.test_structured", observer=beginner.observers[0]
        )
        logger.info("Hello there, {name}!", name="wally")

        # Read the log file and check it has the event we sent
        with open(log_file, "r") as f:
            logged_events = f.read().strip().split("\n")
        self.assertEqual(len(logged_events), 1)

        # The event pulled from the file should render fine
        self.assertTrue(
            logged_events[0].endswith(
                " - tests.logging.test_structured - INFO - None - Hello there, wally!"
            )
        )

    def test_collects_logcontext(self):
        """
        Test that log outputs have the attached logging context.
        """
        log_config = {"drains": {}}

        # Begin the logger with our config
        beginner = FakeBeginner()
        publisher = setup_structured_logging(
            self.hs.config, log_config, logBeginner=beginner
        )

        logs = []

        publisher.addObserver(logs.append)

        # Make a logger and send an event
        logger = Logger(
            namespace="tests.logging.test_structured", observer=beginner.observers[0]
        )

        with LoggingContext("testcontext", request="somereq"):
            logger.info("Hello there, {name}!", name="steve")

        self.assertEqual(len(logs), 1)
        self.assertEqual(logs[0]["request"], "somereq")
