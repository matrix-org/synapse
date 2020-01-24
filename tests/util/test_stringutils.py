# -*- coding: utf-8 -*-
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
from synapse.util.stringutils import assert_valid_client_secret

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
            # We temporarily allow : characters: https://github.com/matrix-org/synapse/issues/6766
            # To be removed in a future release
            "SECRET:1234567890",
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
