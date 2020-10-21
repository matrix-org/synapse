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

from synapse.logging._terse_json import TerseJsonFormatter

from tests.unittest import DEBUG, HomeserverTestCase


class TerseJsonTestCase(HomeserverTestCase):
    @DEBUG
    def test_log_output(self):
        """
        The Terse JSON formatter converts log messages to JSON.
        """
        output = StringIO()

        handler = logging.StreamHandler(output)
        handler.setFormatter(TerseJsonFormatter(metadata={"server_name": "foo"}))

        logger = logging.getLogger()
        logger.addHandler(handler)

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
            "server_name",
        ]
        self.assertCountEqual(log.keys(), expected_log_keys)
        self.assertEqual(log["log"], "Hello there, wally!")
