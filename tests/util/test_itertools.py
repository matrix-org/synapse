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
from synapse.util.iterutils import chunk_seq

from tests.unittest import TestCase


class ChunkSeqTests(TestCase):
    def test_short_seq(self):
        parts = chunk_seq("123", 8)

        self.assertEqual(
            list(parts), ["123"],
        )

    def test_long_seq(self):
        parts = chunk_seq("abcdefghijklmnop", 8)

        self.assertEqual(
            list(parts), ["abcdefgh", "ijklmnop"],
        )

    def test_uneven_parts(self):
        parts = chunk_seq("abcdefghijklmnop", 5)

        self.assertEqual(
            list(parts), ["abcde", "fghij", "klmno", "p"],
        )

    def test_empty_input(self):
        parts = chunk_seq([], 5)

        self.assertEqual(
            list(parts), [],
        )
