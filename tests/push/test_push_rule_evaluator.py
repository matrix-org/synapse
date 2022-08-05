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

from typing import Dict, Optional, Set, Tuple, Union

import frozendict

from twisted.test.proto_helpers import MemoryReactor

import synapse.rest.admin
from synapse.api.constants import EventTypes, Membership
from synapse.api.room_versions import RoomVersions
from synapse.appservice import ApplicationService
from synapse.events import FrozenEvent
from synapse.push import push_rule_evaluator
from synapse.push.push_rule_evaluator import PushRuleEvaluatorForEvent
from synapse.rest.client import login, register, room
from synapse.server import HomeServer
from synapse.storage.databases.main.appservice import _make_exclusive_regex
from synapse.types import JsonDict
from synapse.util import Clock

from tests import unittest
from tests.test_utils.event_injection import create_event, inject_member_event


class PushRuleEvaluatorTestCase(unittest.TestCase):
    def _get_evaluator(
        self,
        content: JsonDict,
        relations: Optional[Dict[str, Set[Tuple[str, str]]]] = None,
        relations_match_enabled: bool = False,
    ) -> PushRuleEvaluatorForEvent:
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
        power_levels: Dict[str, Union[int, Dict[str, int]]] = {}
        return PushRuleEvaluatorForEvent(
            event,
            room_member_count,
            sender_power_level,
            power_levels,
            relations or set(),
            relations_match_enabled,
        )

    def test_display_name(self) -> None:
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
        self, condition: JsonDict, content: JsonDict, msg: Optional[str] = None
    ) -> None:
        evaluator = self._get_evaluator(content)
        self.assertTrue(evaluator.matches(condition, "@user:test", "display_name"), msg)

    def _assert_not_matches(
        self, condition: JsonDict, content: JsonDict, msg: Optional[str] = None
    ) -> None:
        evaluator = self._get_evaluator(content)
        self.assertFalse(
            evaluator.matches(condition, "@user:test", "display_name"), msg
        )

    def test_event_match_body(self) -> None:
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

    def test_event_match_non_body(self) -> None:
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

        # it should work on frozendicts too
        self._assert_matches(
            condition,
            frozendict.frozendict({"value": "FoobaZ"}),
            "patterns should match on frozendicts",
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

    def test_no_body(self) -> None:
        """Not having a body shouldn't break the evaluator."""
        evaluator = self._get_evaluator({})

        condition = {
            "kind": "contains_display_name",
        }
        self.assertFalse(evaluator.matches(condition, "@user:test", "foo"))

    def test_invalid_body(self) -> None:
        """A non-string body should not break the evaluator."""
        condition = {
            "kind": "contains_display_name",
        }

        for body in (1, True, {"foo": "bar"}):
            evaluator = self._get_evaluator({"body": body})
            self.assertFalse(evaluator.matches(condition, "@user:test", "foo"))

    def test_tweaks_for_actions(self) -> None:
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

    def test_relation_match(self) -> None:
        """Test the relation_match push rule kind."""

        # Check if the experimental feature is disabled.
        evaluator = self._get_evaluator(
            {}, {"m.annotation": {("@user:test", "m.reaction")}}
        )
        condition = {"kind": "relation_match"}
        # Oddly, an unknown condition always matches.
        self.assertTrue(evaluator.matches(condition, "@user:test", "foo"))

        # A push rule evaluator with the experimental rule enabled.
        evaluator = self._get_evaluator(
            {}, {"m.annotation": {("@user:test", "m.reaction")}}, True
        )

        # Check just relation type.
        condition = {
            "kind": "org.matrix.msc3772.relation_match",
            "rel_type": "m.annotation",
        }
        self.assertTrue(evaluator.matches(condition, "@user:test", "foo"))

        # Check relation type and sender.
        condition = {
            "kind": "org.matrix.msc3772.relation_match",
            "rel_type": "m.annotation",
            "sender": "@user:test",
        }
        self.assertTrue(evaluator.matches(condition, "@user:test", "foo"))
        condition = {
            "kind": "org.matrix.msc3772.relation_match",
            "rel_type": "m.annotation",
            "sender": "@other:test",
        }
        self.assertFalse(evaluator.matches(condition, "@user:test", "foo"))

        # Check relation type and event type.
        condition = {
            "kind": "org.matrix.msc3772.relation_match",
            "rel_type": "m.annotation",
            "type": "m.reaction",
        }
        self.assertTrue(evaluator.matches(condition, "@user:test", "foo"))

        # Check just sender, this fails since rel_type is required.
        condition = {
            "kind": "org.matrix.msc3772.relation_match",
            "sender": "@user:test",
        }
        self.assertFalse(evaluator.matches(condition, "@user:test", "foo"))

        # Check sender glob.
        condition = {
            "kind": "org.matrix.msc3772.relation_match",
            "rel_type": "m.annotation",
            "sender": "@*:test",
        }
        self.assertTrue(evaluator.matches(condition, "@user:test", "foo"))

        # Check event type glob.
        condition = {
            "kind": "org.matrix.msc3772.relation_match",
            "rel_type": "m.annotation",
            "event_type": "*.reaction",
        }
        self.assertTrue(evaluator.matches(condition, "@user:test", "foo"))


class TestBulkPushRuleEvaluator(unittest.HomeserverTestCase):
    """Tests for the bulk push rule evaluator"""

    servlets = [
        synapse.rest.admin.register_servlets_for_client_rest_resource,
        login.register_servlets,
        register.register_servlets,
        room.register_servlets,
    ]

    def prepare(self, reactor: MemoryReactor, clock: Clock, homeserver: HomeServer):
        # Define an application service so that we can register appservice users
        self._service_token = "some_token"
        self._service = ApplicationService(
            self._service_token,
            "as1",
            "@as.sender:test",
            namespaces={
                "users": [
                    {"regex": "@_as_.*:test", "exclusive": True},
                    {"regex": "@as.sender:test", "exclusive": True},
                ]
            },
            msc3202_transaction_extensions=True,
        )
        self.hs.get_datastores().main.services_cache = [self._service]
        self.hs.get_datastores().main.exclusive_user_regex = _make_exclusive_regex(
            [self._service]
        )

        self._as_user, _ = self.register_appservice_user(
            "_as_user", self._service_token
        )

        self.evaluator = self.hs.get_bulk_push_rule_evaluator()

    def test_ignore_appservice_users(self) -> None:
        "Test that we don't generate push for appservice users"

        user_id = self.register_user("user", "pass")
        token = self.login("user", "pass")

        room_id = self.helper.create_room_as(user_id, tok=token)
        self.get_success(
            inject_member_event(self.hs, room_id, self._as_user, Membership.JOIN)
        )

        event, context = self.get_success(
            create_event(
                self.hs,
                type=EventTypes.Message,
                room_id=room_id,
                sender=user_id,
                content={"body": "test", "msgtype": "m.text"},
            )
        )

        # Assert the returned push rules do not contain the app service user
        rules = self.get_success(self.evaluator._get_rules_for_event(event))
        self.assertTrue(self._as_user not in rules)

        # Assert that no push actions have been added to the staging table (the
        # sender should not be pushed for the event)
        users_with_push_actions = self.get_success(
            self.hs.get_datastores().main.db_pool.simple_select_onecol(
                table="event_push_actions_staging",
                keyvalues={"event_id": event.event_id},
                retcol="user_id",
                desc="test_ignore_appservice_users",
            )
        )

        self.assertEqual(len(users_with_push_actions), 0)
