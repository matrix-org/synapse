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

import logging
import os
import os.path
import shutil
import sys
import textwrap

from twisted.logger import Logger, eventAsText, eventsFromJSONLogFile

from synapse.config.logger import setup_logging
from synapse.logging._structured import setup_structured_logging
from synapse.logging.context import LoggingContext

from tests.unittest import DEBUG, HomeserverTestCase


class FakeBeginner(object):
    def beginLoggingTo(self, observers, **kwargs):
        self.observers = observers


class StructuredLoggingTestBase(object):
    """
    Test base that registers a cleanup handler to reset the stdlib log handler
    to 'unset'.
    """

    def prepare(self, reactor, clock, hs):
        def _cleanup():
            logging.getLogger("synapse").setLevel(logging.NOTSET)

        self.addCleanup(_cleanup)


class StructuredLoggingTestCase(StructuredLoggingTestBase, HomeserverTestCase):
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

        json_log_file = os.path.abspath(os.path.join(temp_dir, "out.json"))

        log_config = {
            "drains": {"jsonfile": {"type": "file_json", "location": json_log_file}}
        }

        # Begin the logger with our config
        beginner = FakeBeginner()
        setup_structured_logging(
            self.hs, self.hs.config, log_config, logBeginner=beginner
        )

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

        log_file = os.path.abspath(os.path.join(temp_dir, "out.log"))

        log_config = {"drains": {"file": {"type": "file", "location": log_file}}}

        # Begin the logger with our config
        beginner = FakeBeginner()
        setup_structured_logging(
            self.hs, self.hs.config, log_config, logBeginner=beginner
        )

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
            self.hs, self.hs.config, log_config, logBeginner=beginner
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


class StructuredLoggingConfigurationFileTestCase(
    StructuredLoggingTestBase, HomeserverTestCase
):
    def make_homeserver(self, reactor, clock):

        tempdir = self.mktemp()
        os.mkdir(tempdir)
        log_config_file = os.path.abspath(os.path.join(tempdir, "log.config.yaml"))
        self.homeserver_log = os.path.abspath(os.path.join(tempdir, "homeserver.log"))

        config = self.default_config()
        config["log_config"] = log_config_file

        with open(log_config_file, "w") as f:
            f.write(
                textwrap.dedent(
                    """\
                    structured: true

                    drains:
                        file:
                            type: file_json
                            location: %s
                    """
                    % (self.homeserver_log,)
                )
            )

        self.addCleanup(self._sys_cleanup)

        return self.setup_test_homeserver(config=config)

    def _sys_cleanup(self):
        sys.stdout = sys.__stdout__
        sys.stderr = sys.__stderr__

    # Do not remove! We need the logging system to be set other than WARNING.
    @DEBUG
    def test_log_output(self):
        """
        When a structured logging config is given, Synapse will use it.
        """
        beginner = FakeBeginner()
        publisher = setup_logging(self.hs, self.hs.config, logBeginner=beginner)

        # Make a logger and send an event
        logger = Logger(namespace="tests.logging.test_structured", observer=publisher)

        with LoggingContext("testcontext", request="somereq"):
            logger.info("Hello there, {name}!", name="steve")

        with open(self.homeserver_log, "r") as f:
            logged_events = [
                eventAsText(x, includeTimestamp=False) for x in eventsFromJSONLogFile(f)
            ]

        logs = "\n".join(logged_events)
        self.assertTrue("***** STARTING SERVER *****" in logs)
        self.assertTrue("Hello there, steve!" in logs)
