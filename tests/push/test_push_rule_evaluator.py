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
