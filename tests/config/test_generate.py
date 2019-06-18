# -*- coding: utf-8 -*-
# Copyright 2016 OpenMarket Ltd
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

import os.path
import re
import shutil
import tempfile

from synapse.config.homeserver import HomeServerConfig

from tests import unittest


class ConfigGenerationTestCase(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.file = os.path.join(self.dir, "homeserver.yaml")

    def tearDown(self):
        shutil.rmtree(self.dir)

    def test_generate_config_generates_files(self):
        HomeServerConfig.load_or_generate_config(
            "",
            [
                "--generate-config",
                "-c",
                self.file,
                "--report-stats=yes",
                "-H",
                "lemurs.win",
            ],
        )

        self.assertSetEqual(
            set(["homeserver.yaml", "lemurs.win.log.config", "lemurs.win.signing.key"]),
            set(os.listdir(self.dir)),
        )

        self.assert_log_filename_is(
            os.path.join(self.dir, "lemurs.win.log.config"),
            os.path.join(os.getcwd(), "homeserver.log"),
        )

    def assert_log_filename_is(self, log_config_file, expected):
        with open(log_config_file) as f:
            config = f.read()
            # find the 'filename' line
            matches = re.findall(r"^\s*filename:\s*(.*)$", config, re.M)
            self.assertEqual(1, len(matches))
            self.assertEqual(matches[0], expected)
