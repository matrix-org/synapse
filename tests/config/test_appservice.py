# Copyright 2023 Matrix.org Foundation C.I.C.
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

from synapse.config.appservice import AppServiceConfig, ConfigError

from tests.unittest import TestCase


class AppServiceConfigTest(TestCase):
    def test_invalid_app_service_config_files(self) -> None:
        for invalid_value in [
            "foobar",
            1,
            None,
            True,
            False,
            {},
            ["foo", "bar", False],
        ]:
            with self.assertRaises(ConfigError):
                AppServiceConfig().read_config(
                    {"app_service_config_files": invalid_value}
                )

    def test_valid_app_service_config_files(self) -> None:
        AppServiceConfig().read_config({"app_service_config_files": []})
        AppServiceConfig().read_config(
            {"app_service_config_files": ["/not/a/real/path", "/not/a/real/path/2"]}
        )
