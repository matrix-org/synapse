# -*- coding: utf-8 -*-
# Copyright 2020 The Matrix.org Foundation C.I.C.
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
from synapse.replication.tcp.commands import (
    RdataCommand,
    ReplicateCommand,
    parse_command_from_line,
)

from tests.unittest import TestCase


class ParseCommandTestCase(TestCase):
    def test_parse_one_word_command(self):
        line = "REPLICATE"
        cmd = parse_command_from_line(line)
        self.assertIsInstance(cmd, ReplicateCommand)

    def test_parse_rdata(self):
        line = 'RDATA events master 6287863 ["ev", ["$eventid", "!roomid", "type", null, null, null]]'
        cmd = parse_command_from_line(line)
        assert isinstance(cmd, RdataCommand)
        self.assertEqual(cmd.stream_name, "events")
        self.assertEqual(cmd.instance_name, "master")
        self.assertEqual(cmd.token, 6287863)

    def test_parse_rdata_batch(self):
        line = 'RDATA presence master batch ["@foo:example.com", "online"]'
        cmd = parse_command_from_line(line)
        assert isinstance(cmd, RdataCommand)
        self.assertEqual(cmd.stream_name, "presence")
        self.assertEqual(cmd.instance_name, "master")
        self.assertIsNone(cmd.token)
