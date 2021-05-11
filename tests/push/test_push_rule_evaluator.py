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

from typing import Any, Dict

from synapse.api.room_versions import RoomVersions
from synapse.events import FrozenEvent
from synapse.push import push_rule_evaluator
from synapse.push.push_rule_evaluator import PushRuleEvaluatorForEvent

from tests import unittest


class PushRuleEvaluatorTestCase(unittest.TestCase):
    def _get_evaluator(self, content):
        event = FrozenEvent(
            {
                "event_id": "$event_id",
                "type": "m.room.history_visibility",
                "sender": "@user:test",
                "state_key": "",
                "room_id": "#room:test",
                "content": content,
            },
            RoomVersions.V1,
        )
        room_member_count = 0
        sender_power_level = 0
        power_levels = {}
        return PushRuleEvaluatorForEvent(
            event, room_member_count, sender_power_level, power_levels
        )

    def test_display_name(self):
        """Check for a matching display name in the body of the event."""
        evaluator = self._get_evaluator({"body": "foo bar baz"})

        condition = {
            "kind": "contains_display_name",
        }

        # Blank names are skipped.
        self.assertFalse(evaluator.matches(condition, "@user:test", ""))

        # Check a display name that doesn't match.
        self.assertFalse(evaluator.matches(condition, "@user:test", "not found"))

        # Check a display name which matches.
        self.assertTrue(evaluator.matches(condition, "@user:test", "foo"))

        # A display name that matches, but not a full word does not result in a match.
        self.assertFalse(evaluator.matches(condition, "@user:test", "ba"))

        # A display name should not be interpreted as a regular expression.
        self.assertFalse(evaluator.matches(condition, "@user:test", "ba[rz]"))

        # A display name with spaces should work fine.
        self.assertTrue(evaluator.matches(condition, "@user:test", "foo bar"))

    def _assert_matches(
        self, condition: Dict[str, Any], content: Dict[str, Any], msg=None
    ) -> None:
        evaluator = self._get_evaluator(content)
        self.assertTrue(evaluator.matches(condition, "@user:test", "display_name"), msg)

    def _assert_not_matches(
        self, condition: Dict[str, Any], content: Dict[str, Any], msg=None
    ) -> None:
        evaluator = self._get_evaluator(content)
        self.assertFalse(
            evaluator.matches(condition, "@user:test", "display_name"), msg
        )

    def test_event_match_body(self):
        """Check that event_match conditions on content.body work as expected"""

        # if the key is `content.body`, the pattern matches substrings.

        # non-wildcards should match
        condition = {
            "kind": "event_match",
            "key": "content.body",
            "pattern": "foobaz",
        }
        self._assert_matches(
            condition,
            {"body": "aaa FoobaZ zzz"},
            "patterns should match and be case-insensitive",
        )
        self._assert_not_matches(
            condition,
            {"body": "aa xFoobaZ yy"},
            "pattern should only match at word boundaries",
        )
        self._assert_not_matches(
            condition,
            {"body": "aa foobazx yy"},
            "pattern should only match at word boundaries",
        )

        # wildcards should match
        condition = {
            "kind": "event_match",
            "key": "content.body",
            "pattern": "f?o*baz",
        }

        self._assert_matches(
            condition,
            {"body": "aaa FoobarbaZ zzz"},
            "* should match string and pattern should be case-insensitive",
        )
        self._assert_matches(
            condition, {"body": "aa foobaz yy"}, "* should match 0 characters"
        )
        self._assert_not_matches(
            condition, {"body": "aa fobbaz yy"}, "? should not match 0 characters"
        )
        self._assert_not_matches(
            condition, {"body": "aa fiiobaz yy"}, "? should not match 2 characters"
        )
        self._assert_not_matches(
            condition,
            {"body": "aa xfooxbaz yy"},
            "pattern should only match at word boundaries",
        )
        self._assert_not_matches(
            condition,
            {"body": "aa fooxbazx yy"},
            "pattern should only match at word boundaries",
        )

        # test backslashes
        condition = {
            "kind": "event_match",
            "key": "content.body",
            "pattern": r"f\oobaz",
        }
        self._assert_matches(
            condition,
            {"body": r"F\oobaz"},
            "backslash should match itself",
        )
        condition = {
            "kind": "event_match",
            "key": "content.body",
            "pattern": r"f\?obaz",
        }
        self._assert_matches(
            condition,
            {"body": r"F\oobaz"},
            r"? after \ should match any character",
        )

    def test_event_match_non_body(self):
        """Check that event_match conditions on other keys work as expected"""

        # if the key is anything other than 'content.body', the pattern must match the
        # whole value.

        # non-wildcards should match
        condition = {
            "kind": "event_match",
            "key": "content.value",
            "pattern": "foobaz",
        }
        self._assert_matches(
            condition,
            {"value": "FoobaZ"},
            "patterns should match and be case-insensitive",
        )
        self._assert_not_matches(
            condition,
            {"value": "xFoobaZ"},
            "pattern should only match at the start/end of the value",
        )
        self._assert_not_matches(
            condition,
            {"value": "FoobaZz"},
            "pattern should only match at the start/end of the value",
        )

        # wildcards should match
        condition = {
            "kind": "event_match",
            "key": "content.value",
            "pattern": "f?o*baz",
        }
        self._assert_matches(
            condition,
            {"value": "FoobarbaZ"},
            "* should match string and pattern should be case-insensitive",
        )
        self._assert_matches(
            condition, {"value": "foobaz"}, "* should match 0 characters"
        )
        self._assert_not_matches(
            condition, {"value": "fobbaz"}, "? should not match 0 characters"
        )
        self._assert_not_matches(
            condition, {"value": "fiiobaz"}, "? should not match 2 characters"
        )
        self._assert_not_matches(
            condition,
            {"value": "xfooxbaz"},
            "pattern should only match at the start/end of the value",
        )
        self._assert_not_matches(
            condition,
            {"value": "fooxbazx"},
            "pattern should only match at the start/end of the value",
        )
        self._assert_not_matches(
            condition,
            {"value": "x\nfooxbaz"},
            "pattern should not match after a newline",
        )
        self._assert_not_matches(
            condition,
            {"value": "fooxbaz\nx"},
            "pattern should not match before a newline",
        )

    def test_no_body(self):
        """Not having a body shouldn't break the evaluator."""
        evaluator = self._get_evaluator({})

        condition = {
            "kind": "contains_display_name",
        }
        self.assertFalse(evaluator.matches(condition, "@user:test", "foo"))

    def test_invalid_body(self):
        """A non-string body should not break the evaluator."""
        condition = {
            "kind": "contains_display_name",
        }

        for body in (1, True, {"foo": "bar"}):
            evaluator = self._get_evaluator({"body": body})
            self.assertFalse(evaluator.matches(condition, "@user:test", "foo"))

    def test_tweaks_for_actions(self):
        """
        This tests the behaviour of tweaks_for_actions.
        """

        actions = [
            {"set_tweak": "sound", "value": "default"},
            {"set_tweak": "highlight"},
            "notify",
        ]

        self.assertEqual(
            push_rule_evaluator.tweaks_for_actions(actions),
            {"sound": "default", "highlight": True},
        )
