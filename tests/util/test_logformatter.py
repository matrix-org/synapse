# -*- coding: utf-8 -*-
# Copyright 2018 New Vector Ltd
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

from synapse.util.logformatter import LogFormatter

from tests import unittest


class TestException(Exception):
    pass


class LogFormatterTestCase(unittest.TestCase):
    def test_formatter(self):
        formatter = LogFormatter()

        try:
            raise TestException("testytest")
        except TestException:
            ei = sys.exc_info()

        output = formatter.formatException(ei)

        # check the output looks vaguely sane
        self.assertIn("testytest", output)
        self.assertIn("Capture point", output)
