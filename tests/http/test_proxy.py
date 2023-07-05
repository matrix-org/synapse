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
from typing import Set

from parameterized import parameterized

from synapse.http.proxy import parse_connection_header_value

from tests.unittest import TestCase


class ProxyTests(TestCase):
    @parameterized.expand(
        [
            [b"close, X-Foo, X-Bar", {"Close", "X-Foo", "X-Bar"}],
            # No whitespace
            [b"close,X-Foo,X-Bar", {"Close", "X-Foo", "X-Bar"}],
            # More whitespace
            [b"close,    X-Foo,      X-Bar", {"Close", "X-Foo", "X-Bar"}],
            # "close" directive in not the first position
            [b"X-Foo, X-Bar, close", {"X-Foo", "X-Bar", "Close"}],
            # Normalizes header capitalization
            [b"keep-alive, x-fOo, x-bAr", {"Keep-Alive", "X-Foo", "X-Bar"}],
            # Handles header names with whitespace
            [
                b"keep-alive, x  foo, x bar",
                {"Keep-Alive", "X  foo", "X bar"},
            ],
        ]
    )
    def test_parse_connection_header_value(
        self,
        connection_header_value: bytes,
        expected_extra_headers_to_remove: Set[str],
    ) -> None:
        """
        Tests that the connection header value is parsed correctly
        """
        self.assertEqual(
            expected_extra_headers_to_remove,
            parse_connection_header_value(connection_header_value),
        )
