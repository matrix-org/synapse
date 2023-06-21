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
import base64
import logging
import os
from typing import List, Optional, Set
from unittest.mock import patch

from parameterized import parameterized

from synapse.http.proxy import parse_connection_header_value

from tests.unittest import TestCase


class ProxyTests(TestCase):
    @parameterized.expand(
        [
            [b"close, X-Foo, X-Bar", "close", set(["X-Foo", "X-Bar"])],
            # No whitespace
            [b"close,X-Foo,X-Bar", "close", set(["X-Foo", "X-Bar"])],
            # More whitespace
            [b"close,    X-Foo,      X-Bar", "close", set(["X-Foo", "X-Bar"])],
            # Keeps connection captilization and normalizes headers
            [b"kEep-AliVe, x-foo, x-bar", "kEep-AliVe", set(["X-Foo", "X-Bar"])],
            # Handles header names with whitespace
            [b"keep-alive, x  foo, x bar", "keep-alive", set(["X  foo", "X bar"])],
        ]
    )
    def test_parse_connection_header_value(
        self,
        connection_header_value: str,
        expected_connection: Optional[str],
        expected_extra_headers_to_remove: Set[str],
    ) -> None:
        """
        Tests that the connection header value is parsed correctly
        """
        self.assertEqual(
            (
                expected_connection,
                expected_extra_headers_to_remove,
            ),
            parse_connection_header_value(connection_header_value),
        )
