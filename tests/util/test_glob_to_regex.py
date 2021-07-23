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
from synapse.util import glob_to_regex

from tests.unittest import TestCase


class GlobToRegexTestCase(TestCase):
    def test_literal_match(self):
        """patterns without wildcards should match"""
        pat = glob_to_regex("foobaz")
        self.assertTrue(
            pat.match("FoobaZ"), "patterns should match and be case-insensitive"
        )
        self.assertFalse(
            pat.match("x foobaz"), "pattern should not match at word boundaries"
        )

    def test_wildcard_match(self):
        pat = glob_to_regex("f?o*baz")

        self.assertTrue(
            pat.match("FoobarbaZ"),
            "* should match string and pattern should be case-insensitive",
        )
        self.assertTrue(pat.match("foobaz"), "* should match 0 characters")
        self.assertFalse(pat.match("fooxaz"), "the character after * must match")
        self.assertFalse(pat.match("fobbaz"), "? should not match 0 characters")
        self.assertFalse(pat.match("fiiobaz"), "? should not match 2 characters")

    def test_multi_wildcard(self):
        """patterns with multiple wildcards in a row should match"""
        pat = glob_to_regex("**baz")
        self.assertTrue(pat.match("agsgsbaz"), "** should match any string")
        self.assertTrue(pat.match("baz"), "** should match the empty string")
        self.assertEqual(pat.pattern, r"\A.{0,}baz\Z")

        pat = glob_to_regex("*?baz")
        self.assertTrue(pat.match("agsgsbaz"), "*? should match any string")
        self.assertTrue(pat.match("abaz"), "*? should match a single char")
        self.assertFalse(pat.match("baz"), "*? should not match the empty string")
        self.assertEqual(pat.pattern, r"\A.{1,}baz\Z")

        pat = glob_to_regex("a?*?*?baz")
        self.assertTrue(pat.match("a g baz"), "?*?*? should match 3 chars")
        self.assertFalse(pat.match("a..baz"), "?*?*? should not match 2 chars")
        self.assertTrue(pat.match("a.gg.baz"), "?*?*? should match 4 chars")
        self.assertEqual(pat.pattern, r"\Aa.{3,}baz\Z")
