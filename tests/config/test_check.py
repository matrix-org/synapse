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
import shutil
import tempfile
import yaml
from synapse.config.homeserver import HomeServerConfig
from tests import unittest


class ConfigLoadingTestCase(unittest.TestCase):

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        print(self.dir)
        self.file = os.path.join(self.dir, "homeserver.yaml")

    def tearDown(self):
        shutil.rmtree(self.dir)

    def test_load_fails_if_server_name_missing(self):
        self.generate_config()
        self.remove_lines_containing("server_name")
        with self.assertRaises(Exception):
            HomeServerConfig.load_config("", ["--check-config", "-c", self.file])
        with self.assertRaises(Exception):
            HomeServerConfig.load_or_generate_config("", ["--check-config", "-c", self.file])

    def test_generated_config_passes_check(self):
        self.generate_config()

        config = HomeServerConfig.load_config("", ["--check-config", "-c", self.file])
        config = HomeServerConfig.load_or_generate_config("", ["--check-config", "-c", self.file])

    def test_invalid_key(self):
        self.generate_config()
        self.add_lines_to_config([
            "lemurs_key: 125123",
        ])
        config = HomeServerConfig.load_config("", ["--check-config", "-c", self.file])

    def generate_config(self):
        HomeServerConfig.load_or_generate_config("", [
            "--generate-config",
            "-c", self.file,
            "--report-stats=yes",
            "-H", "lemurs.win"
        ])

    def remove_lines_containing(self, needle):
        with open(self.file, "r") as f:
            contents = f.readlines()
        contents = [l for l in contents if needle not in l]
        with open(self.file, "w") as f:
            f.write("".join(contents))

    def add_lines_to_config(self, lines):
        with open(self.file, "a") as f:
            for line in lines:
                f.write(line + "\n")
