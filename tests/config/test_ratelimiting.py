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
from synapse.config.homeserver import HomeServerConfig
from synapse.config.ratelimiting import RatelimitSettings

from tests.unittest import TestCase
from tests.utils import default_config


class ParseRatelimitSettingsTestcase(TestCase):
    def test_depth_1(self) -> None:
        cfg = {
            "a": {
                "per_second": 5,
                "burst_count": 10,
            }
        }
        parsed = RatelimitSettings.parse(cfg, "a")
        self.assertEqual(parsed, RatelimitSettings("a", 5, 10))

    def test_depth_2(self) -> None:
        cfg = {
            "a": {
                "b": {
                    "per_second": 5,
                    "burst_count": 10,
                },
            }
        }
        parsed = RatelimitSettings.parse(cfg, "a.b")
        self.assertEqual(parsed, RatelimitSettings("a.b", 5, 10))

    def test_missing(self) -> None:
        parsed = RatelimitSettings.parse(
            {}, "a", defaults={"per_second": 5, "burst_count": 10}
        )
        self.assertEqual(parsed, RatelimitSettings("a", 5, 10))


class RatelimitConfigTestCase(TestCase):
    def test_parse_rc_federation(self) -> None:
        config_dict = default_config("test")
        config_dict["rc_federation"] = {
            "window_size": 20000,
            "sleep_limit": 693,
            "sleep_delay": 252,
            "reject_limit": 198,
            "concurrent": 7,
        }

        config = HomeServerConfig()
        config.parse_config_dict(config_dict, "", "")
        config_obj = config.ratelimiting.rc_federation

        self.assertEqual(config_obj.window_size, 20000)
        self.assertEqual(config_obj.sleep_limit, 693)
        self.assertEqual(config_obj.sleep_delay, 252)
        self.assertEqual(config_obj.reject_limit, 198)
        self.assertEqual(config_obj.concurrent, 7)
