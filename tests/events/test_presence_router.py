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
from typing import Dict, Iterable, List, Optional, Set, Tuple, Union
from unittest.mock import Mock

import attr

from synapse.api.constants import EduTypes
from synapse.events.presence_router import PresenceRouter, load_legacy_presence_router
from synapse.federation.units import Transaction
from synapse.handlers.presence import UserPresenceState
from synapse.module_api import ModuleApi
from synapse.rest import admin
from synapse.rest.client import login, presence, room
from synapse.types import JsonDict, StreamToken, create_requester

from tests.handlers.test_sync import generate_sync_config
from tests.test_utils import simple_async_mock
from tests.unittest import FederatingHomeserverTestCase, TestCase, override_config


@attr.s
class PresenceRouterTestConfig:
    users_who_should_receive_all_presence = attr.ib(type=List[str], default=[])


class LegacyPresenceRouterTestModule:
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
    ) -> Union[Set[str], PresenceRouter.ALL_USERS]:
        if user_id in self._config.users_who_should_receive_all_presence:
            return PresenceRouter.ALL_USERS

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


class PresenceRouterTestModule:
    def __init__(self, config: PresenceRouterTestConfig, api: ModuleApi):
        self._config = config
        self._module_api = api
        api.register_presence_router_callbacks(
            get_users_for_states=self.get_users_for_states,
            get_interested_users=self.get_interested_users,
        )

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
    ) -> Union[Set[str], PresenceRouter.ALL_USERS]:
        if user_id in self._config.users_who_should_receive_all_presence:
            return PresenceRouter.ALL_USERS

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


class PresenceRouterTestCase(FederatingHomeserverTestCase):
    servlets = [
        admin.register_servlets,
        login.register_servlets,
        room.register_servlets,
        presence.register_servlets,
    ]

    def make_homeserver(self, reactor, clock):
        # Mock out the calls over federation.
        fed_transport_client = Mock(spec=["send_transaction"])
        fed_transport_client.send_transaction = simple_async_mock({})

        hs = self.setup_test_homeserver(
            federation_transport_client=fed_transport_client,
        )
        # Load the modules into the homeserver
        module_api = hs.get_module_api()
        for module, config in hs.config.modules.loaded_modules:
            module(config=config, api=module_api)

        load_legacy_presence_router(hs)

        return hs

    def prepare(self, reactor, clock, homeserver):
        self.sync_handler = self.hs.get_sync_handler()
        self.module_api = homeserver.get_module_api()

    @override_config(
        {
            "presence": {
                "presence_router": {
                    "module": __name__ + ".LegacyPresenceRouterTestModule",
                    "config": {
                        "users_who_should_receive_all_presence": [
                            "@presence_gobbler:test",
                        ]
                    },
                }
            },
            "send_federation": True,
        }
    )
    def test_receiving_all_presence_legacy(self):
        self.receiving_all_presence_test_body()

    @override_config(
        {
            "modules": [
                {
                    "module": __name__ + ".PresenceRouterTestModule",
                    "config": {
                        "users_who_should_receive_all_presence": [
                            "@presence_gobbler:test",
                        ]
                    },
                },
            ],
            "send_federation": True,
        }
    )
    def test_receiving_all_presence(self):
        self.receiving_all_presence_test_body()

    def receiving_all_presence_test_body(self):
        """Test that a user that does not share a room with another other can receive
        presence for them, due to presence routing.
        """
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
        room_id = self.helper.create_room_as(
            self.other_user_one_id, tok=self.other_user_one_tok
        )

        self.helper.invite(
            room_id,
            self.other_user_one_id,
            self.other_user_two_id,
            tok=self.other_user_one_tok,
        )
        self.helper.join(room_id, self.other_user_two_id, tok=self.other_user_two_tok)
        # User one sends some presence
        send_presence_update(
            self,
            self.other_user_one_id,
            self.other_user_one_tok,
            "online",
            "boop",
        )

        # Check that the presence receiving user gets user one's presence when syncing
        presence_updates, sync_token = sync_presence(
            self, self.presence_receiving_user_id
        )
        self.assertEqual(len(presence_updates), 1)

        presence_update: UserPresenceState = presence_updates[0]
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
        presence_updates, _ = sync_presence(
            self, self.presence_receiving_user_id, sync_token
        )
        self.assertEqual(len(presence_updates), 3)

        # But that User One only get itself and User Two's presence
        presence_updates, _ = sync_presence(self, self.other_user_one_id)
        self.assertEqual(len(presence_updates), 2)

        found = False
        for update in presence_updates:
            if update.user_id == self.other_user_two_id:
                self.assertEqual(update.state, "online")
                self.assertEqual(update.status_msg, "user_two")
                found = True

        self.assertTrue(found)

    @override_config(
        {
            "presence": {
                "presence_router": {
                    "module": __name__ + ".LegacyPresenceRouterTestModule",
                    "config": {
                        "users_who_should_receive_all_presence": [
                            "@presence_gobbler1:test",
                            "@presence_gobbler2:test",
                            "@far_away_person:island",
                        ]
                    },
                }
            },
            "send_federation": True,
        }
    )
    def test_send_local_online_presence_to_with_module_legacy(self):
        self.send_local_online_presence_to_with_module_test_body()

    @override_config(
        {
            "modules": [
                {
                    "module": __name__ + ".PresenceRouterTestModule",
                    "config": {
                        "users_who_should_receive_all_presence": [
                            "@presence_gobbler1:test",
                            "@presence_gobbler2:test",
                            "@far_away_person:island",
                        ]
                    },
                },
            ],
            "send_federation": True,
        }
    )
    def test_send_local_online_presence_to_with_module(self):
        self.send_local_online_presence_to_with_module_test_body()

    def send_local_online_presence_to_with_module_test_body(self):
        """Tests that send_local_presence_to_users sends local online presence to a set
        of specified local and remote users, with a custom PresenceRouter module enabled.
        """
        # Create a user who will send presence updates
        self.other_user_id = self.register_user("other_user", "monkey")
        self.other_user_tok = self.login("other_user", "monkey")

        # And another two users that will also send out presence updates, as well as receive
        # theirs and everyone else's
        self.presence_receiving_user_one_id = self.register_user(
            "presence_gobbler1", "monkey"
        )
        self.presence_receiving_user_one_tok = self.login("presence_gobbler1", "monkey")
        self.presence_receiving_user_two_id = self.register_user(
            "presence_gobbler2", "monkey"
        )
        self.presence_receiving_user_two_tok = self.login("presence_gobbler2", "monkey")

        # Have all three users send some presence updates
        send_presence_update(
            self,
            self.other_user_id,
            self.other_user_tok,
            "online",
            "I'm online!",
        )
        send_presence_update(
            self,
            self.presence_receiving_user_one_id,
            self.presence_receiving_user_one_tok,
            "online",
            "I'm also online!",
        )
        send_presence_update(
            self,
            self.presence_receiving_user_two_id,
            self.presence_receiving_user_two_tok,
            "unavailable",
            "I'm in a meeting!",
        )

        # Mark each presence-receiving user for receiving all user presence
        self.get_success(
            self.module_api.send_local_online_presence_to(
                [
                    self.presence_receiving_user_one_id,
                    self.presence_receiving_user_two_id,
                ]
            )
        )

        # Perform a sync for each user

        # The other user should only receive their own presence
        presence_updates, _ = sync_presence(self, self.other_user_id)
        self.assertEqual(len(presence_updates), 1)

        presence_update: UserPresenceState = presence_updates[0]
        self.assertEqual(presence_update.user_id, self.other_user_id)
        self.assertEqual(presence_update.state, "online")
        self.assertEqual(presence_update.status_msg, "I'm online!")

        # Whereas both presence receiving users should receive everyone's presence updates
        presence_updates, _ = sync_presence(self, self.presence_receiving_user_one_id)
        self.assertEqual(len(presence_updates), 3)
        presence_updates, _ = sync_presence(self, self.presence_receiving_user_two_id)
        self.assertEqual(len(presence_updates), 3)

        # We stagger sending of presence, so we need to wait a bit for them to
        # get sent out.
        self.reactor.advance(60)

        # Test that sending to a remote user works
        remote_user_id = "@far_away_person:island"

        # Note that due to the remote user being in our module's
        # users_who_should_receive_all_presence config, they would have
        # received user presence updates already.
        #
        # Thus we reset the mock, and try sending all online local user
        # presence again
        self.hs.get_federation_transport_client().send_transaction.reset_mock()

        # Broadcast local user online presence
        self.get_success(
            self.module_api.send_local_online_presence_to([remote_user_id])
        )

        # We stagger sending of presence, so we need to wait a bit for them to
        # get sent out.
        self.reactor.advance(60)

        # Check that the expected presence updates were sent
        # We explicitly compare using sets as we expect that calling
        # module_api.send_local_online_presence_to will create a presence
        # update that is a duplicate of the specified user's current presence.
        # These are sent to clients and will be picked up below, thus we use a
        # set to deduplicate. We're just interested that non-offline updates were
        # sent out for each user ID.
        expected_users = {
            self.other_user_id,
            self.presence_receiving_user_one_id,
            self.presence_receiving_user_two_id,
        }
        found_users = set()

        calls = (
            self.hs.get_federation_transport_client().send_transaction.call_args_list
        )
        for call in calls:
            call_args = call[0]
            federation_transaction: Transaction = call_args[0]

            # Get the sent EDUs in this transaction
            edus = federation_transaction.get_dict()["edus"]

            for edu in edus:
                # Make sure we're only checking presence-type EDUs
                if edu["edu_type"] != EduTypes.PRESENCE:
                    continue

                # EDUs can contain multiple presence updates
                for presence_update in edu["content"]["push"]:
                    # Check for presence updates that contain the user IDs we're after
                    found_users.add(presence_update["user_id"])

                    # Ensure that no offline states are being sent out
                    self.assertNotEqual(presence_update["presence"], "offline")

        self.assertEqual(found_users, expected_users)


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
    since_token: Optional[StreamToken] = None,
) -> Tuple[List[UserPresenceState], StreamToken]:
    """Perform a sync request for the given user and return the user presence updates
    they've received, as well as the next_batch token.

    This method assumes testcase.sync_handler points to the homeserver's sync handler.

    Args:
        testcase: The testcase that is currently being run.
        user_id: The ID of the user to generate a sync response for.
        since_token: An optional token to indicate from at what point to sync from.

    Returns:
        A tuple containing a list of presence updates, and the sync response's
        next_batch token.
    """
    requester = create_requester(user_id)
    sync_config = generate_sync_config(requester.user.to_string())
    sync_result = testcase.get_success(
        testcase.sync_handler.wait_for_sync_for_user(
            requester, sync_config, since_token
        )
    )

    return sync_result.presence, sync_result.next_batch
