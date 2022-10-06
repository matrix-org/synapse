from unittest.mock import patch

from synapse.api.room_versions import RoomVersions
from synapse.push.bulk_push_rule_evaluator import BulkPushRuleEvaluator
from synapse.rest import admin
from synapse.rest.client import login, register, room
from synapse.types import create_requester

from tests import unittest


class TestBulkPushRuleEvaluator(unittest.HomeserverTestCase):

    servlets = [
        admin.register_servlets_for_client_rest_resource,
        room.register_servlets,
        login.register_servlets,
        register.register_servlets,
    ]

    def test_action_for_event_by_user_handles_noninteger_power_levels(self) -> None:
        """We should convert floats and strings to integers before passing to Rust.

        Reproduces #14060.

        A lack of validation: the gift that keeps on giving.
        """
        # Create a new user and room.
        alice = self.register_user("alice", "pass")
        token = self.login(alice, "pass")

        room_id = self.helper.create_room_as(
            alice, room_version=RoomVersions.V9.identifier, tok=token
        )

        # Alter the power levels in that room to include stringy and floaty levels.
        # We need to suppress the validation logic or else it will reject these dodgy
        # values. (Presumably this validation was not always present.)
        event_creation_handler = self.hs.get_event_creation_handler()
        requester = create_requester(alice)
        with patch("synapse.events.validator.validate_canonicaljson"), patch(
            "synapse.events.validator.jsonschema.validate"
        ):
            self.helper.send_state(
                room_id,
                "m.room.power_levels",
                {
                    "users": {alice: "100"},  # stringy
                    "notifications": {"room": 100.0},  # float
                },
                token,
                state_key="",
            )

        # Create a new message event, and try to evaluate it under the dodgy
        # power level event.
        event, context = self.get_success(
            event_creation_handler.create_event(
                requester,
                {
                    "type": "m.room.message",
                    "room_id": room_id,
                    "content": {
                        "msgtype": "m.text",
                        "body": "helo",
                    },
                    "sender": alice,
                },
            )
        )

        bulk_evaluator = BulkPushRuleEvaluator(self.hs)
        # should not raise
        self.get_success(bulk_evaluator.action_for_event_by_user(event, context))
