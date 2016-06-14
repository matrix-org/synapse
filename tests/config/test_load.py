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
        print self.dir
        self.file = os.path.join(self.dir, "homeserver.yaml")

    def tearDown(self):
        shutil.rmtree(self.dir)

    def test_load_fails_if_server_name_missing(self):
        self.generate_config_and_remove_lines_containing("server_name")
        with self.assertRaises(Exception):
            HomeServerConfig.load_config("", ["-c", self.file])
        with self.assertRaises(Exception):
            HomeServerConfig.load_or_generate_config("", ["-c", self.file])

    def test_generates_and_loads_macaroon_secret_key(self):
        self.generate_config()

        with open(self.file,
                  "r") as f:
            raw = yaml.load(f)
        self.assertIn("macaroon_secret_key", raw)

        config = HomeServerConfig.load_config("", ["-c", self.file])
        self.assertTrue(
            hasattr(config, "macaroon_secret_key"),
            "Want config to have attr macaroon_secret_key"
        )
        if len(config.macaroon_secret_key) < 5:
            self.fail(
                "Want macaroon secret key to be string of at least length 5,"
                "was: %r" % (config.macaroon_secret_key,)
            )

        config = HomeServerConfig.load_or_generate_config("", ["-c", self.file])
        self.assertTrue(
            hasattr(config, "macaroon_secret_key"),
            "Want config to have attr macaroon_secret_key"
        )
        if len(config.macaroon_secret_key) < 5:
            self.fail(
                "Want macaroon secret key to be string of at least length 5,"
                "was: %r" % (config.macaroon_secret_key,)
            )

    def test_load_succeeds_if_macaroon_secret_key_missing(self):
        self.generate_config_and_remove_lines_containing("macaroon")
        config1 = HomeServerConfig.load_config("", ["-c", self.file])
        config2 = HomeServerConfig.load_config("", ["-c", self.file])
        config3 = HomeServerConfig.load_or_generate_config("", ["-c", self.file])
        self.assertEqual(config1.macaroon_secret_key, config2.macaroon_secret_key)
        self.assertEqual(config1.macaroon_secret_key, config3.macaroon_secret_key)

    def test_disable_registration(self):
        self.generate_config()
        self.add_lines_to_config([
            "enable_registration: true",
            "disable_registration: true",
        ])
        # Check that disable_registration clobbers enable_registration.
        config = HomeServerConfig.load_config("", ["-c", self.file])
        self.assertFalse(config.enable_registration)

        config = HomeServerConfig.load_or_generate_config("", ["-c", self.file])
        self.assertFalse(config.enable_registration)

        # Check that either config value is clobbered by the command line.
        config = HomeServerConfig.load_or_generate_config("", [
            "-c", self.file, "--enable-registration"
        ])
        self.assertTrue(config.enable_registration)

    def generate_config(self):
        HomeServerConfig.load_or_generate_config("", [
            "--generate-config",
            "-c", self.file,
            "--report-stats=yes",
            "-H", "lemurs.win"
        ])

    def generate_config_and_remove_lines_containing(self, needle):
        self.generate_config()

        with open(self.file, "r") as f:
            contents = f.readlines()
        contents = [l for l in contents if needle not in l]
        with open(self.file, "w") as f:
            f.write("".join(contents))

    def add_lines_to_config(self, lines):
        with open(self.file, "a") as f:
            for line in lines:
                f.write(line + "\n")
