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

from synapse.config import ConfigError
from synapse.config._util import validate_config

from tests.unittest import TestCase


class ValidateConfigTestCase(TestCase):
    """Test cases for synapse.config._util.validate_config"""

    def test_bad_object_in_array(self):
        """malformed objects within an array should be validated correctly"""

        # consider a structure:
        #
        # array_of_objs:
        #   - r: 1
        #     foo: 2
        #
        #   - r: 2
        #     bar: 3
        #
        # ... where each entry must contain an "r": check that the path
        # to the required item is correclty reported.

        schema = {
            "type": "object",
            "properties": {
                "array_of_objs": {
                    "type": "array",
                    "items": {"type": "object", "required": ["r"]},
                },
            },
        }

        with self.assertRaises(ConfigError) as c:
            validate_config(schema, {"array_of_objs": [{}]}, ("base",))

        self.assertEqual(c.exception.path, ["base", "array_of_objs", "<item 0>"])
