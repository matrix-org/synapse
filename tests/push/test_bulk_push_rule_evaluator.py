# Copyright 2022 The Matrix.org Foundation C.I.C.
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

from typing import Any, Optional
from unittest.mock import AsyncMock, patch

from parameterized import parameterized

from twisted.test.proto_helpers import MemoryReactor

from synapse.api.constants import EventContentFields, RelationTypes
from synapse.api.room_versions import RoomVersions
from synapse.push.bulk_push_rule_evaluator import BulkPushRuleEvaluator
from synapse.rest import admin
from synapse.rest.client import login, register, room
from synapse.server import HomeServer
from synapse.types import JsonDict, create_requester
from synapse.util import Clock

from tests.unittest import HomeserverTestCase, override_config


class TestBulkPushRuleEvaluator(HomeserverTestCase):
    servlets = [
        admin.register_servlets_for_client_rest_resource,
        room.register_servlets,
        login.register_servlets,
        register.register_servlets,
    ]

    def prepare(
        self, reactor: MemoryReactor, clock: Clock, homeserver: HomeServer
    ) -> None:
        # Create a new user and room.
        self.alice = self.register_user("alice", "pass")
        self.token = self.login(self.alice, "pass")
        self.requester = create_requester(self.alice)

        self.room_id = self.helper.create_room_as(
            # This is deliberately set to V9, because we want to test the logic which
            # handles stringy power levels. Stringy power levels were outlawed in V10.
            self.alice,
            room_version=RoomVersions.V9.identifier,
            tok=self.token,
        )

        self.event_creation_handler = self.hs.get_event_creation_handler()

    @parameterized.expand(
        [
            # The historically-permitted bad values. Alice's notification should be
            # allowed if this threshold is at or below her power level (60)
            ("100", False),
            ("0", True),
            (12.34, True),
            (60.0, True),
            (67.89, False),
            # Values that int(...) would not successfully cast should be ignored.
            # The room notification level should then default to 50, per the spec, so
            # Alice's notification is allowed.
            (None, True),
            # We haven't seen `"room": []` or `"room": {}` in the wild (yet), but
            # let's check them for paranoia's sake.
            ([], True),
            ({}, True),
        ]
    )
    def test_action_for_event_by_user_handles_noninteger_room_power_levels(
        self, bad_room_level: object, should_permit: bool
    ) -> None:
        """We should convert strings in `room` to integers before passing to Rust.

        Test this as follows:
        - Create a room as Alice and invite two other users Bob and Charlie.
        - Set PLs so that Alice has PL 60 and `notifications.room` is set to a bad value.
        - Have Alice create a message notifying @room.
        - Evaluate notification actions for that message. This should not raise.
        - Look in the DB to see if that message triggered a highlight for Bob.

        The test is parameterised with two arguments:
        - the bad power level value for "room", before JSON serisalistion
        - whether Bob should expect the message to be highlighted

        Reproduces https://github.com/matrix-org/synapse/issues/14060.

        A lack of validation: the gift that keeps on giving.
        """
        # Join another user to the room, so that there is someone to see Alice's
        # @room notification.
        bob = self.register_user("bob", "pass")
        bob_token = self.login(bob, "pass")
        self.helper.join(self.room_id, bob, tok=bob_token)

        # Alter the power levels in that room to include the bad @room notification
        # level. We need to suppress
        #
        # - canonicaljson validation, because canonicaljson forbids floats;
        # - the event jsonschema validation, because it will forbid bad values; and
        # - the auth rules checks, because they stop us from creating power levels
        #   with `"room": null`. (We want to test this case, because we have seen it
        #   in the wild.)
        #
        # We have seen stringy and null values for "room" in the wild, so presumably
        # some of this validation was missing in the past.
        with patch("synapse.events.validator.validate_canonicaljson"), patch(
            "synapse.events.validator.jsonschema.validate"
        ), patch("synapse.handlers.event_auth.check_state_dependent_auth_rules"):
            pl_event_id = self.helper.send_state(
                self.room_id,
                "m.room.power_levels",
                {
                    "users": {self.alice: 60},
                    "notifications": {"room": bad_room_level},
                },
                self.token,
                state_key="",
            )["event_id"]

        # Create a new message event, and try to evaluate it under the dodgy
        # power level event.
        event, unpersisted_context = self.get_success(
            self.event_creation_handler.create_event(
                self.requester,
                {
                    "type": "m.room.message",
                    "room_id": self.room_id,
                    "content": {
                        "msgtype": "m.text",
                        "body": "helo @room",
                    },
                    "sender": self.alice,
                },
                prev_event_ids=[pl_event_id],
            )
        )
        context = self.get_success(unpersisted_context.persist(event))

        bulk_evaluator = BulkPushRuleEvaluator(self.hs)
        # should not raise
        self.get_success(bulk_evaluator.action_for_events_by_user([(event, context)]))

        # Did Bob see Alice's @room notification?
        highlighted_actions = self.get_success(
            self.hs.get_datastores().main.db_pool.simple_select_list(
                table="event_push_actions_staging",
                keyvalues={
                    "event_id": event.event_id,
                    "user_id": bob,
                    "highlight": 1,
                },
                retcols=("*",),
                desc="get_event_push_actions_staging",
            )
        )
        self.assertEqual(len(highlighted_actions), int(should_permit))

    @override_config({"push": {"enabled": False}})
    def test_action_for_event_by_user_disabled_by_config(self) -> None:
        """Ensure that push rules are not calculated when disabled in the config"""

        # Create a new message event which should cause a notification.
        event, unpersisted_context = self.get_success(
            self.event_creation_handler.create_event(
                self.requester,
                {
                    "type": "m.room.message",
                    "room_id": self.room_id,
                    "content": {
                        "msgtype": "m.text",
                        "body": "helo",
                    },
                    "sender": self.alice,
                },
            )
        )
        context = self.get_success(unpersisted_context.persist(event))

        bulk_evaluator = BulkPushRuleEvaluator(self.hs)
        # Mock the method which calculates push rules -- we do this instead of
        # e.g. checking the results in the database because we want to ensure
        # that code isn't even running.
        bulk_evaluator._action_for_event_by_user = AsyncMock()  # type: ignore[method-assign]

        # Ensure no actions are generated!
        self.get_success(bulk_evaluator.action_for_events_by_user([(event, context)]))
        bulk_evaluator._action_for_event_by_user.assert_not_called()

    def _create_and_process(
        self, bulk_evaluator: BulkPushRuleEvaluator, content: Optional[JsonDict] = None
    ) -> bool:
        """Returns true iff the `mentions` trigger an event push action."""
        # Create a new message event which should cause a notification.
        event, unpersisted_context = self.get_success(
            self.event_creation_handler.create_event(
                self.requester,
                {
                    "type": "test",
                    "room_id": self.room_id,
                    "content": content or {},
                    "sender": f"@bob:{self.hs.hostname}",
                },
            )
        )
        context = self.get_success(unpersisted_context.persist(event))
        # Execute the push rule machinery.
        self.get_success(bulk_evaluator.action_for_events_by_user([(event, context)]))

        # If any actions are generated for this event, return true.
        result = self.get_success(
            self.hs.get_datastores().main.db_pool.simple_select_list(
                table="event_push_actions_staging",
                keyvalues={"event_id": event.event_id},
                retcols=("*",),
                desc="get_event_push_actions_staging",
            )
        )
        return len(result) > 0

    def test_user_mentions(self) -> None:
        """Test the behavior of an event which includes invalid user mentions."""
        bulk_evaluator = BulkPushRuleEvaluator(self.hs)

        # Not including the mentions field should not notify.
        self.assertFalse(self._create_and_process(bulk_evaluator))
        # An empty mentions field should not notify.
        self.assertFalse(
            self._create_and_process(bulk_evaluator, {EventContentFields.MENTIONS: {}})
        )

        # Non-dict mentions should be ignored.
        #
        # Avoid C-S validation as these aren't expected.
        with patch(
            "synapse.events.validator.EventValidator.validate_new",
            new=lambda s, event, config: True,
        ):
            mentions: Any
            for mentions in (None, True, False, 1, "foo", []):
                self.assertFalse(
                    self._create_and_process(
                        bulk_evaluator, {EventContentFields.MENTIONS: mentions}
                    )
                )

            # A non-list should be ignored.
            for mentions in (None, True, False, 1, "foo", {}):
                self.assertFalse(
                    self._create_and_process(
                        bulk_evaluator,
                        {EventContentFields.MENTIONS: {"user_ids": mentions}},
                    )
                )

        # The Matrix ID appearing anywhere in the list should notify.
        self.assertTrue(
            self._create_and_process(
                bulk_evaluator,
                {EventContentFields.MENTIONS: {"user_ids": [self.alice]}},
            )
        )
        self.assertTrue(
            self._create_and_process(
                bulk_evaluator,
                {
                    EventContentFields.MENTIONS: {
                        "user_ids": ["@another:test", self.alice]
                    }
                },
            )
        )

        # Duplicate user IDs should notify.
        self.assertTrue(
            self._create_and_process(
                bulk_evaluator,
                {EventContentFields.MENTIONS: {"user_ids": [self.alice, self.alice]}},
            )
        )

        # Invalid entries in the list are ignored.
        #
        # Avoid C-S validation as these aren't expected.
        with patch(
            "synapse.events.validator.EventValidator.validate_new",
            new=lambda s, event, config: True,
        ):
            self.assertFalse(
                self._create_and_process(
                    bulk_evaluator,
                    {
                        EventContentFields.MENTIONS: {
                            "user_ids": [None, True, False, {}, []]
                        }
                    },
                )
            )
            self.assertTrue(
                self._create_and_process(
                    bulk_evaluator,
                    {
                        EventContentFields.MENTIONS: {
                            "user_ids": [None, True, False, {}, [], self.alice]
                        }
                    },
                )
            )

        # The legacy push rule should not mention if the mentions field exists.
        self.assertFalse(
            self._create_and_process(
                bulk_evaluator,
                {
                    "body": self.alice,
                    "msgtype": "m.text",
                    EventContentFields.MENTIONS: {},
                },
            )
        )

    def test_room_mentions(self) -> None:
        """Test the behavior of an event which includes invalid room mentions."""
        bulk_evaluator = BulkPushRuleEvaluator(self.hs)

        # Room mentions from those without power should not notify.
        self.assertFalse(
            self._create_and_process(
                bulk_evaluator, {EventContentFields.MENTIONS: {"room": True}}
            )
        )

        # Room mentions from those with power should notify.
        self.helper.send_state(
            self.room_id,
            "m.room.power_levels",
            {"notifications": {"room": 0}},
            self.token,
            state_key="",
        )
        self.assertTrue(
            self._create_and_process(
                bulk_evaluator, {EventContentFields.MENTIONS: {"room": True}}
            )
        )

        # Invalid data should not notify.
        #
        # Avoid C-S validation as these aren't expected.
        with patch(
            "synapse.events.validator.EventValidator.validate_new",
            new=lambda s, event, config: True,
        ):
            mentions: Any
            for mentions in (None, False, 1, "foo", [], {}):
                self.assertFalse(
                    self._create_and_process(
                        bulk_evaluator,
                        {EventContentFields.MENTIONS: {"room": mentions}},
                    )
                )

        # The legacy push rule should not mention if the mentions field exists.
        self.assertFalse(
            self._create_and_process(
                bulk_evaluator,
                {
                    "body": "@room",
                    "msgtype": "m.text",
                    EventContentFields.MENTIONS: {},
                },
            )
        )

    def test_suppress_edits(self) -> None:
        """Under the default push rules, event edits should not generate notifications."""
        bulk_evaluator = BulkPushRuleEvaluator(self.hs)

        # Create & persist an event to use as the parent of the relation.
        event, unpersisted_context = self.get_success(
            self.event_creation_handler.create_event(
                self.requester,
                {
                    "type": "m.room.message",
                    "room_id": self.room_id,
                    "content": {
                        "msgtype": "m.text",
                        "body": "helo",
                    },
                    "sender": self.alice,
                },
            )
        )
        context = self.get_success(unpersisted_context.persist(event))
        self.get_success(
            self.event_creation_handler.handle_new_client_event(
                self.requester, events_and_context=[(event, context)]
            )
        )

        # The edit should not cause a notification.
        self.assertFalse(
            self._create_and_process(
                bulk_evaluator,
                {
                    "body": "Test message",
                    "m.relates_to": {
                        "rel_type": RelationTypes.REPLACE,
                        "event_id": event.event_id,
                    },
                },
            )
        )

        # An edit which is a mention will cause a notification.
        self.assertTrue(
            self._create_and_process(
                bulk_evaluator,
                {
                    "body": "Test message",
                    "m.relates_to": {
                        "rel_type": RelationTypes.REPLACE,
                        "event_id": event.event_id,
                    },
                    "m.mentions": {
                        "user_ids": [self.alice],
                    },
                },
            )
        )
