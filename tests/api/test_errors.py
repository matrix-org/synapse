# Copyright 2023 The Matrix.org Foundation C.I.C.
#
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

from synapse.api.errors import LimitExceededError
from synapse.config.homeserver import HomeServerConfig

from tests import unittest
from tests.utils import default_config


class ErrorsTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.config = HomeServerConfig()
        self.config.parse_config_dict(
            {
                **default_config("test"),
                "experimental_features": {"msc4041_enabled": True},
            },
            "",
            "",
        )

    def test_limit_exceeded_header(self) -> None:
        err = LimitExceededError(retry_after_ms=100)
        self.assertEqual(err.error_dict(self.config).get("retry_after_ms"), 100)
        headers = err.headers_dict(self.config)
        assert headers is not None
        self.assertEqual(headers.get("Retry-After"), "1")

    def test_limit_exceeded_rounding(self) -> None:
        err = LimitExceededError(retry_after_ms=3001)
        self.assertEqual(err.error_dict(None).get("retry_after_ms"), 3001)
        headers = err.headers_dict(self.config)
        assert headers is not None
        self.assertEqual(headers.get("Retry-After"), "4")
