# -*- coding: utf-8 -*-
# Copyright 2021 The Matrix.org Foundation C.I.C.
#
# Licensed under the Apache License, Version 2.0 (the 'License');
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an 'AS IS' BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
from typing import Dict, Iterable, List, Optional, Set, Union

import attr
from typing_extensions import Literal

from synapse.handlers.presence import UserPresenceState
from synapse.module_api import ModuleApi
from synapse.rest import admin
from synapse.rest.client.v1 import login, presence, room
from synapse.types import JsonDict, create_requester

from tests import unittest
from tests.handlers.test_sync import generate_sync_config
from tests.unittest import TestCase


@attr.s
class PresenceRouterTestConfig:
    users_who_should_receive_all_presence = attr.ib(type=List[str], default=[])


class PresenceRouterTestModule:
    def __init__(self, config: PresenceRouterTestConfig, module_api: ModuleApi):
        self._config = config
        self._module_api = module_api

    async def get_users_for_states(
        self, state_updates: Iterable[UserPresenceState]
    ) -> Dict[str, Set[UserPresenceState]]:
        users_to_state = {
            user_id: set(state_updates)
            for user_id in self._config.users_who_should_receive_all_presence
        }
        return users_to_state

    async def get_interested_users(
        self, user_id: str
    ) -> Union[Set[str], Literal["ALL"]]:
        print()
        if user_id in self._config.users_who_should_receive_all_presence:
            return "ALL"

        return set()

    @staticmethod
    def parse_config(config_dict: dict) -> PresenceRouterTestConfig:
        """Parse a configuration dictionary from the homeserver config, do
        some validation and return a typed PresenceRouterConfig.

        Args:
            config_dict: The configuration dictionary.

        Returns:
            A validated config object.
        """
        # Initialise a typed config object
        config = PresenceRouterTestConfig()

        config.users_who_should_receive_all_presence = config_dict.get(
            "users_who_should_receive_all_presence"
        )

        return config


class PresenceRouterTestCase(unittest.HomeserverTestCase):
    servlets = [
        admin.register_servlets,
        login.register_servlets,
        room.register_servlets,
        presence.register_servlets,
    ]

    def default_config(self):
        config = super().default_config()
        config["presence"] = {
            "presence_router": {
                "module": __name__ + ".PresenceRouterTestModule",
                "config": {
                    "users_who_should_receive_all_presence": ["@presence_gobbler:test"]
                },
            }
        }
        return config

    def prepare(self, reactor, clock, homeserver):
        self.sync_handler = self.hs.get_sync_handler()

        # Create a user who should receive all presence of others
        self.presence_receiving_user_id = self.register_user(
            "presence_gobbler", "monkey"
        )
        self.presence_receiving_user_tok = self.login("presence_gobbler", "monkey")

        # And two users who should not have any special routing
        self.other_user_one_id = self.register_user("other_user_one", "monkey")
        self.other_user_one_tok = self.login("other_user_one", "monkey")
        self.other_user_two_id = self.register_user("other_user_two", "monkey")
        self.other_user_two_tok = self.login("other_user_two", "monkey")

        # Put the other two users in a room with each other
        self.room_id = self.helper.create_room_as(
            self.other_user_one_id, tok=self.other_user_one_tok
        )

        self.helper.invite(
            self.room_id,
            self.other_user_one_id,
            self.other_user_two_id,
            tok=self.other_user_one_tok,
        )
        self.helper.join(
            self.room_id, self.other_user_two_id, tok=self.other_user_two_tok
        )

    def test_receiving_all_presence(self):
        """Test that a user that does not share a room with another other can receive
        presence for them, due to presence routing.
        """
        # User one sends some presence
        send_presence_update(
            self,
            self.other_user_one_id,
            self.other_user_one_tok,
            "online",
            "boop",
        )

        # Check that the presence receiving user gets user one's presence when syncing
        presence_updates = sync_presence(self, self.presence_receiving_user_id)
        self.assertEqual(len(presence_updates), 1)

        presence_update = presence_updates[0]  # type: UserPresenceState
        self.assertEqual(presence_update.user_id, self.other_user_one_id)
        self.assertEqual(presence_update.state, "online")
        self.assertEqual(presence_update.status_msg, "boop")

        # Have all three users send presence
        send_presence_update(
            self,
            self.other_user_one_id,
            self.other_user_one_tok,
            "online",
            "user_one",
        )
        send_presence_update(
            self,
            self.other_user_two_id,
            self.other_user_two_tok,
            "online",
            "user_two",
        )
        send_presence_update(
            self,
            self.presence_receiving_user_id,
            self.presence_receiving_user_tok,
            "online",
            "presence_gobbler",
        )

        # Check that the presence receiving user gets everyone's presence
        presence_updates = sync_presence(self, self.presence_receiving_user_id)
        self.assertEqual(len(presence_updates), 3)

        # But that User One only get itself and User Two's presence
        presence_updates = sync_presence(self, self.other_user_one_id)
        self.assertEqual(len(presence_updates), 2)

        found = False
        for update in presence_updates:
            if update.user_id == self.other_user_two_id:
                self.assertEqual(update.state, "online")
                self.assertEqual(update.status_msg, "user_two")
                found = True

        self.assertTrue(found)


def send_presence_update(
    testcase: TestCase,
    user_id: str,
    access_token: str,
    presence_state: str,
    status_message: Optional[str] = None,
) -> JsonDict:
    # Build the presence body
    body = {"presence": presence_state}
    if status_message:
        body["status_msg"] = status_message

    # Update the user's presence state
    channel = testcase.make_request(
        "PUT", "/presence/%s/status" % (user_id,), body, access_token=access_token
    )
    testcase.assertEqual(channel.code, 200)

    return channel.json_body


def sync_presence(
    testcase: TestCase,
    user_id: str,
) -> List[UserPresenceState]:
    requester = create_requester(user_id)
    sync_config = generate_sync_config(requester.user.to_string())
    sync_result = testcase.get_success(
        testcase.sync_handler.wait_for_sync_for_user(requester, sync_config)
    )

    return sync_result.presence
