# Copyright 2016 OpenMarket Ltd
# Copyright 2021 The Matrix.org Foundation C.I.C.
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
import yaml

from synapse.config import ConfigError
from synapse.config.homeserver import HomeServerConfig

from tests.config.utils import ConfigFileTestCase


class ConfigLoadingFileTestCase(ConfigFileTestCase):
    def test_load_fails_if_server_name_missing(self):
        self.generate_config_and_remove_lines_containing("server_name")
        with self.assertRaises(ConfigError):
            HomeServerConfig.load_config("", ["-c", self.config_file])
        with self.assertRaises(ConfigError):
            HomeServerConfig.load_or_generate_config("", ["-c", self.config_file])

    def test_generates_and_loads_macaroon_secret_key(self):
        self.generate_config()

        with open(self.config_file) as f:
            raw = yaml.safe_load(f)
        self.assertIn("macaroon_secret_key", raw)

        config = HomeServerConfig.load_config("", ["-c", self.config_file])
        self.assertTrue(
            hasattr(config.key, "macaroon_secret_key"),
            "Want config to have attr macaroon_secret_key",
        )
        if len(config.key.macaroon_secret_key) < 5:
            self.fail(
                "Want macaroon secret key to be string of at least length 5,"
                "was: %r" % (config.key.macaroon_secret_key,)
            )

        config2 = HomeServerConfig.load_or_generate_config("", ["-c", self.config_file])
        assert config2 is not None
        self.assertTrue(
            hasattr(config2.key, "macaroon_secret_key"),
            "Want config to have attr macaroon_secret_key",
        )
        if len(config2.key.macaroon_secret_key) < 5:
            self.fail(
                "Want macaroon secret key to be string of at least length 5,"
                "was: %r" % (config2.key.macaroon_secret_key,)
            )

    def test_load_succeeds_if_macaroon_secret_key_missing(self):
        self.generate_config_and_remove_lines_containing("macaroon")
        config1 = HomeServerConfig.load_config("", ["-c", self.config_file])
        config2 = HomeServerConfig.load_config("", ["-c", self.config_file])
        config3 = HomeServerConfig.load_or_generate_config("", ["-c", self.config_file])
        assert config1 is not None
        assert config2 is not None
        assert config3 is not None
        self.assertEqual(
            config1.key.macaroon_secret_key, config2.key.macaroon_secret_key
        )
        self.assertEqual(
            config1.key.macaroon_secret_key, config3.key.macaroon_secret_key
        )

    def test_disable_registration(self):
        self.generate_config()
        self.add_lines_to_config(
            ["enable_registration: true", "disable_registration: true"]
        )
        # Check that disable_registration clobbers enable_registration.
        config = HomeServerConfig.load_config("", ["-c", self.config_file])
        self.assertFalse(config.registration.enable_registration)

        config2 = HomeServerConfig.load_or_generate_config("", ["-c", self.config_file])
        assert config2 is not None
        self.assertFalse(config2.registration.enable_registration)

        # Check that either config value is clobbered by the command line.
        config3 = HomeServerConfig.load_or_generate_config(
            "", ["-c", self.config_file, "--enable-registration"]
        )
        assert config3 is not None
        self.assertTrue(config3.registration.enable_registration)

    def test_stats_enabled(self):
        self.generate_config_and_remove_lines_containing("enable_metrics")
        self.add_lines_to_config(["enable_metrics: true"])

        # The default Metrics Flags are off by default.
        config = HomeServerConfig.load_config("", ["-c", self.config_file])
        self.assertFalse(config.metrics.metrics_flags.known_servers)

    def test_depreciated_identity_server_flag_throws_error(self):
        self.generate_config()
        # Needed to ensure that actual key/value pair added below don't end up on a line with a comment
        self.add_lines_to_config([" "])
        # Check that presence of "trust_identity_server_for_password" throws config error
        self.add_lines_to_config(["trust_identity_server_for_password_resets: true"])
        with self.assertRaises(ConfigError):
            HomeServerConfig.load_config("", ["-c", self.config_file])
