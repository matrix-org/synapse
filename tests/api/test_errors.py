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

from tests import unittest


class ErrorsTestCase(unittest.TestCase):
    def test_limit_exceeded_header(self) -> None:
        err = LimitExceededError(retry_after_ms=100)
        self.assertEqual(err.error_dict({}).get("retry_after_ms"), 100)
        self.assertEqual(err.headers.get("Retry-After"), "1")

    def test_limit_exceeded_rounding(self) -> None:
        err = LimitExceededError(retry_after_ms=3001)
        self.assertEqual(err.error_dict({}).get("retry_after_ms"), 3001)
        self.assertEqual(err.headers.get("Retry-After"), "4")
