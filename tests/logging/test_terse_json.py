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
import logging
from io import StringIO

from synapse.logging._terse_json import JsonFormatter, TerseJsonFormatter

from tests.logging import LoggerCleanupMixin
from tests.unittest import TestCase


class TerseJsonTestCase(LoggerCleanupMixin, TestCase):
    def test_terse_json_output(self):
        """
        The Terse JSON formatter converts log messages to JSON.
        """
        output = StringIO()

        handler = logging.StreamHandler(output)
        handler.setFormatter(TerseJsonFormatter())
        logger = self.get_logger(handler)

        logger.info("Hello there, %s!", "wally")

        # One log message, with a single trailing newline.
        data = output.getvalue()
        logs = data.splitlines()
        self.assertEqual(len(logs), 1)
        self.assertEqual(data.count("\n"), 1)
        log = json.loads(logs[0])

        # The terse logger should give us these keys.
        expected_log_keys = [
            "log",
            "time",
            "level",
            "namespace",
        ]
        self.assertCountEqual(log.keys(), expected_log_keys)
        self.assertEqual(log["log"], "Hello there, wally!")

    def test_extra_data(self):
        """
        Additional information can be included in the structured logging.
        """
        output = StringIO()

        handler = logging.StreamHandler(output)
        handler.setFormatter(TerseJsonFormatter())
        logger = self.get_logger(handler)

        logger.info(
            "Hello there, %s!", "wally", extra={"foo": "bar", "int": 3, "bool": True}
        )

        # One log message, with a single trailing newline.
        data = output.getvalue()
        logs = data.splitlines()
        self.assertEqual(len(logs), 1)
        self.assertEqual(data.count("\n"), 1)
        log = json.loads(logs[0])

        # The terse logger should give us these keys.
        expected_log_keys = [
            "log",
            "time",
            "level",
            "namespace",
            # The additional keys given via extra.
            "foo",
            "int",
            "bool",
        ]
        self.assertCountEqual(log.keys(), expected_log_keys)

        # Check the values of the extra fields.
        self.assertEqual(log["foo"], "bar")
        self.assertEqual(log["int"], 3)
        self.assertIs(log["bool"], True)

    def test_json_output(self):
        """
        The Terse JSON formatter converts log messages to JSON.
        """
        output = StringIO()

        handler = logging.StreamHandler(output)
        handler.setFormatter(JsonFormatter())
        logger = self.get_logger(handler)

        logger.info("Hello there, %s!", "wally")

        # One log message, with a single trailing newline.
        data = output.getvalue()
        logs = data.splitlines()
        self.assertEqual(len(logs), 1)
        self.assertEqual(data.count("\n"), 1)
        log = json.loads(logs[0])

        # The terse logger should give us these keys.
        expected_log_keys = [
            "log",
            "level",
            "namespace",
        ]
        self.assertCountEqual(log.keys(), expected_log_keys)
        self.assertEqual(log["log"], "Hello there, wally!")
