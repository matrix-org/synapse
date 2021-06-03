# Copyright 2020 The Matrix.org Foundation C.I.C.
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
from io import BytesIO
from unittest.mock import Mock

from synapse.api.errors import SynapseError
from synapse.http.servlet import (
    parse_json_object_from_request,
    parse_json_value_from_request,
)

from tests import unittest


def make_request(content):
    """Make an object that acts enough like a request."""
    request = Mock(spec=["content"])

    if isinstance(content, dict):
        content = json.dumps(content).encode("utf8")

    request.content = BytesIO(content)
    return request


class TestServletUtils(unittest.TestCase):
    def test_parse_json_value(self):
        """Basic tests for parse_json_value_from_request."""
        # Test round-tripping.
        obj = {"foo": 1}
        result = parse_json_value_from_request(make_request(obj))
        self.assertEqual(result, obj)

        # Results don't have to be objects.
        result = parse_json_value_from_request(make_request(b'["foo"]'))
        self.assertEqual(result, ["foo"])

        # Test empty.
        with self.assertRaises(SynapseError):
            parse_json_value_from_request(make_request(b""))

        result = parse_json_value_from_request(make_request(b""), allow_empty_body=True)
        self.assertIsNone(result)

        # Invalid UTF-8.
        with self.assertRaises(SynapseError):
            parse_json_value_from_request(make_request(b"\xFF\x00"))

        # Invalid JSON.
        with self.assertRaises(SynapseError):
            parse_json_value_from_request(make_request(b"foo"))

        with self.assertRaises(SynapseError):
            parse_json_value_from_request(make_request(b'{"foo": Infinity}'))

    def test_parse_json_object(self):
        """Basic tests for parse_json_object_from_request."""
        # Test empty.
        result = parse_json_object_from_request(
            make_request(b""), allow_empty_body=True
        )
        self.assertEqual(result, {})

        # Test not an object
        with self.assertRaises(SynapseError):
            parse_json_object_from_request(make_request(b'["foo"]'))
