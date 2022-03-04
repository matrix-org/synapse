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

from synapse.api.errors import SynapseError
from synapse.util.stringutils import (
    assert_valid_client_secret,
    base62_encode,
    parse_server_name,
    parse_and_validate_server_name,
)

from .. import unittest


class StringUtilsTestCase(unittest.TestCase):
    def test_client_secret_regex(self):
        """Ensure that client_secret does not contain illegal characters"""
        good = [
            "abcde12345",
            "ABCabc123",
            "_--something==_",
            "...--==-18913",
            "8Dj2odd-e9asd.cd==_--ddas-secret-",
        ]

        bad = [
            "--+-/secret",
            "\\dx--dsa288",
            "",
            "AAS//",
            "asdj**",
            ">X><Z<!!-)))",
            "a@b.com",
        ]

        for client_secret in good:
            assert_valid_client_secret(client_secret)

        for client_secret in bad:
            with self.assertRaises(SynapseError):
                assert_valid_client_secret(client_secret)

    def test_base62_encode(self):
        self.assertEqual("0", base62_encode(0))
        self.assertEqual("10", base62_encode(62))
        self.assertEqual("1c", base62_encode(100))
        self.assertEqual("001c", base62_encode(100, minwidth=4))

    def test_parse_server_name(self):
        vals = [
            ("localhost:80", ("localhost", 80)),
            ("", ("", None)),
            (":80", ("", 80)),
            ("[::1]", ("[::1]", None)),
            ("[::1]:80", ("[::1]", 80)),
            ("[::1:80", ("[::1", 80)),
        ]
        for value, expected in vals:
            self.assertEqual(parse_server_name(value), expected)

    def test_valid_server_name(self):
        valid_server_names = [
            ("foo.bar.baz:80", ("foo.bar.baz", 80)),
            ("[::1]:80", ("[::1]", 80)),
            ("127.0.0.1:80", ("127.0.0.1", 80)),
            ("foo.bar.baz", ("foo.bar.baz", None)),
            ("[::1]", ("[::1]", None)),
            ("127.0.0.1", ("127.0.0.1", None)),
            ("localhost", ("localhost", None)),
        ]
        for name, expected in valid_server_names:
            self.assertEqual(expected, parse_and_validate_server_name(name))

    def test_invalid_server_name(self):
        invalid_server_names = [
            ("[::1:80", r"Mismatched \[\.\.\.\] in server name '\[::1:80'"),
            ("", "Server name '' has an invalid format"),
            ("[]:80", r"Server name '\[\]:80' is not a valid IPv6 address"),
            (".baz:80", r"Server name '.baz:80' has an invalid format"),
        ]
        for server_name, regex in invalid_server_names:
            with self.assertRaisesRegex(ValueError, regex):
                parse_and_validate_server_name(server_name)
