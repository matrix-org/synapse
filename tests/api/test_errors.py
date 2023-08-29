# Copyright 2023 The Matrix.org Foundation C.I.C.
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

import json

from synapse.api.errors import LimitExceededError

from tests.unittest import TestCase


class LimitExceededErrorTestCase(TestCase):
    def test_key_appears_in_context_but_not_error_dict(self) -> None:
        err = LimitExceededError("needle")
        serialised = json.dumps(err.error_dict(None))
        self.assertIn("needle", err.debug_context)
        self.assertNotIn("needle", serialised)
