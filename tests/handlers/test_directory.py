# Copyright 2014-2016 OpenMarket Ltd
# Copyright 2021 Matrix.org Foundation C.I.C.
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
from typing import Any, Awaitable, Callable, Dict
from unittest.mock import Mock

from twisted.test.proto_helpers import MemoryReactor

import synapse.api.errors
import synapse.rest.admin
from synapse.api.constants import EventTypes
from synapse.rest.client import directory, login, room
from synapse.server import HomeServer
from synapse.types import JsonDict, RoomAlias, create_requester
from synapse.util import Clock

from tests import unittest
from tests.test_utils import make_awaitable


class DirectoryTestCase(unittest.HomeserverTestCase):
    """Tests the directory service."""

    def make_homeserver(self, reactor: MemoryReactor, clock: Clock) -> HomeServer:
        self.mock_federation = Mock()
        self.mock_registry = Mock()

        self.query_handlers: Dict[str, Callable[[dict], Awaitable[JsonDict]]] = {}

        def register_query_handler(
            query_type: str, handler: Callable[[dict], Awaitable[JsonDict]]
        ) -> None:
            self.query_handlers[query_type] = handler

        self.mock_registry.register_query_handler = register_query_handler

        hs = self.setup_test_homeserver(
            federation_client=self.mock_federation,
            federation_registry=self.mock_registry,
        )

        self.handler = hs.get_directory_handler()

        self.store = hs.get_datastores().main

        self.my_room = RoomAlias.from_string("#my-room:test")
        self.your_room = RoomAlias.from_string("#your-room:test")
        self.remote_room = RoomAlias.from_string("#another:remote")

        return hs

    def test_get_local_association(self) -> None:
        self.get_success(
            self.store.create_room_alias_association(
                self.my_room, "!8765qwer:test", ["test"]
            )
        )

        result = self.get_success(self.handler.get_association(self.my_room))

        self.assertEqual({"room_id": "!8765qwer:test", "servers": ["test"]}, result)

    def test_get_remote_association(self) -> None:
        self.mock_federation.make_query.return_value = make_awaitable(
            {"room_id": "!8765qwer:test", "servers": ["test", "remote"]}
        )

        result = self.get_success(self.handler.get_association(self.remote_room))

        self.assertEqual(
            {"room_id": "!8765qwer:test", "servers": ["test", "remote"]}, result
        )
        self.mock_federation.make_query.assert_called_with(
            destination="remote",
            query_type="directory",
            args={"room_alias": "#another:remote"},
            retry_on_dns_fail=False,
            ignore_backoff=True,
        )

    def test_incoming_fed_query(self) -> None:
        self.get_success(
            self.store.create_room_alias_association(
                self.your_room, "!8765asdf:test", ["test"]
            )
        )

        response = self.get_success(
            self.handler.on_directory_query({"room_alias": "#your-room:test"})
        )

        self.assertEqual({"room_id": "!8765asdf:test", "servers": ["test"]}, response)


class TestCreateAlias(unittest.HomeserverTestCase):
    servlets = [
        synapse.rest.admin.register_servlets,
        login.register_servlets,
        room.register_servlets,
        directory.register_servlets,
    ]

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self.handler = hs.get_directory_handler()

        # Create user
        self.admin_user = self.register_user("admin", "pass", admin=True)
        self.admin_user_tok = self.login("admin", "pass")

        # Create a test room
        self.room_id = self.helper.create_room_as(
            self.admin_user, tok=self.admin_user_tok
        )

        self.test_alias = "#test:test"
        self.room_alias = RoomAlias.from_string(self.test_alias)

        # Create a test user.
        self.test_user = self.register_user("user", "pass", admin=False)
        self.test_user_tok = self.login("user", "pass")
        self.helper.join(room=self.room_id, user=self.test_user, tok=self.test_user_tok)

    def test_create_alias_joined_room(self) -> None:
        """A user can create an alias for a room they're in."""
        self.get_success(
            self.handler.create_association(
                create_requester(self.test_user),
                self.room_alias,
                self.room_id,
            )
        )

    def test_create_alias_other_room(self) -> None:
        """A user cannot create an alias for a room they're NOT in."""
        other_room_id = self.helper.create_room_as(
            self.admin_user, tok=self.admin_user_tok
        )

        self.get_failure(
            self.handler.create_association(
                create_requester(self.test_user),
                self.room_alias,
                other_room_id,
            ),
            synapse.api.errors.SynapseError,
        )

    def test_create_alias_admin(self) -> None:
        """An admin can create an alias for a room they're NOT in."""
        other_room_id = self.helper.create_room_as(
            self.test_user, tok=self.test_user_tok
        )

        self.get_success(
            self.handler.create_association(
                create_requester(self.admin_user),
                self.room_alias,
                other_room_id,
            )
        )


class TestDeleteAlias(unittest.HomeserverTestCase):
    servlets = [
        synapse.rest.admin.register_servlets,
        login.register_servlets,
        room.register_servlets,
        directory.register_servlets,
    ]

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self.store = hs.get_datastores().main
        self.handler = hs.get_directory_handler()
        self.state_handler = hs.get_state_handler()

        # Create user
        self.admin_user = self.register_user("admin", "pass", admin=True)
        self.admin_user_tok = self.login("admin", "pass")

        # Create a test room
        self.room_id = self.helper.create_room_as(
            self.admin_user, tok=self.admin_user_tok
        )

        self.test_alias = "#test:test"
        self.room_alias = RoomAlias.from_string(self.test_alias)

        # Create a test user.
        self.test_user = self.register_user("user", "pass", admin=False)
        self.test_user_tok = self.login("user", "pass")
        self.helper.join(room=self.room_id, user=self.test_user, tok=self.test_user_tok)

    def _create_alias(self, user) -> None:
        # Create a new alias to this room.
        self.get_success(
            self.store.create_room_alias_association(
                self.room_alias, self.room_id, ["test"], user
            )
        )

    def test_delete_alias_not_allowed(self) -> None:
        """A user that doesn't meet the expected guidelines cannot delete an alias."""
        self._create_alias(self.admin_user)
        self.get_failure(
            self.handler.delete_association(
                create_requester(self.test_user), self.room_alias
            ),
            synapse.api.errors.AuthError,
        )

    def test_delete_alias_creator(self) -> None:
        """An alias creator can delete their own alias."""
        # Create an alias from a different user.
        self._create_alias(self.test_user)

        # Delete the user's alias.
        result = self.get_success(
            self.handler.delete_association(
                create_requester(self.test_user), self.room_alias
            )
        )
        self.assertEqual(self.room_id, result)

        # Confirm the alias is gone.
        self.get_failure(
            self.handler.get_association(self.room_alias),
            synapse.api.errors.SynapseError,
        )

    def test_delete_alias_admin(self) -> None:
        """A server admin can delete an alias created by another user."""
        # Create an alias from a different user.
        self._create_alias(self.test_user)

        # Delete the user's alias as the admin.
        result = self.get_success(
            self.handler.delete_association(
                create_requester(self.admin_user), self.room_alias
            )
        )
        self.assertEqual(self.room_id, result)

        # Confirm the alias is gone.
        self.get_failure(
            self.handler.get_association(self.room_alias),
            synapse.api.errors.SynapseError,
        )

    def test_delete_alias_sufficient_power(self) -> None:
        """A user with a sufficient power level should be able to delete an alias."""
        self._create_alias(self.admin_user)

        # Increase the user's power level.
        self.helper.send_state(
            self.room_id,
            "m.room.power_levels",
            {"users": {self.test_user: 100}},
            tok=self.admin_user_tok,
        )

        # They can now delete the alias.
        result = self.get_success(
            self.handler.delete_association(
                create_requester(self.test_user), self.room_alias
            )
        )
        self.assertEqual(self.room_id, result)

        # Confirm the alias is gone.
        self.get_failure(
            self.handler.get_association(self.room_alias),
            synapse.api.errors.SynapseError,
        )


class CanonicalAliasTestCase(unittest.HomeserverTestCase):
    """Test modifications of the canonical alias when delete aliases."""

    servlets = [
        synapse.rest.admin.register_servlets,
        login.register_servlets,
        room.register_servlets,
        directory.register_servlets,
    ]

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self.store = hs.get_datastores().main
        self.handler = hs.get_directory_handler()
        self.state_handler = hs.get_state_handler()
        self._storage_controllers = hs.get_storage_controllers()

        # Create user
        self.admin_user = self.register_user("admin", "pass", admin=True)
        self.admin_user_tok = self.login("admin", "pass")

        # Create a test room
        self.room_id = self.helper.create_room_as(
            self.admin_user, tok=self.admin_user_tok
        )

        self.test_alias = "#test:test"
        self.room_alias = self._add_alias(self.test_alias)

    def _add_alias(self, alias: str) -> RoomAlias:
        """Add an alias to the test room."""
        room_alias = RoomAlias.from_string(alias)

        # Create a new alias to this room.
        self.get_success(
            self.store.create_room_alias_association(
                room_alias, self.room_id, ["test"], self.admin_user
            )
        )
        return room_alias

    def _set_canonical_alias(self, content) -> None:
        """Configure the canonical alias state on the room."""
        self.helper.send_state(
            self.room_id,
            "m.room.canonical_alias",
            content,
            tok=self.admin_user_tok,
        )

    def _get_canonical_alias(self):
        """Get the canonical alias state of the room."""
        return self.get_success(
            self._storage_controllers.state.get_current_state_event(
                self.room_id, EventTypes.CanonicalAlias, ""
            )
        )

    def test_remove_alias(self) -> None:
        """Removing an alias that is the canonical alias should remove it there too."""
        # Set this new alias as the canonical alias for this room
        self._set_canonical_alias(
            {"alias": self.test_alias, "alt_aliases": [self.test_alias]}
        )

        data = self._get_canonical_alias()
        self.assertEqual(data["content"]["alias"], self.test_alias)
        self.assertEqual(data["content"]["alt_aliases"], [self.test_alias])

        # Finally, delete the alias.
        self.get_success(
            self.handler.delete_association(
                create_requester(self.admin_user), self.room_alias
            )
        )

        data = self._get_canonical_alias()
        self.assertNotIn("alias", data["content"])
        self.assertNotIn("alt_aliases", data["content"])

    def test_remove_other_alias(self) -> None:
        """Removing an alias listed as in alt_aliases should remove it there too."""
        # Create a second alias.
        other_test_alias = "#test2:test"
        other_room_alias = self._add_alias(other_test_alias)

        # Set the alias as the canonical alias for this room.
        self._set_canonical_alias(
            {
                "alias": self.test_alias,
                "alt_aliases": [self.test_alias, other_test_alias],
            }
        )

        data = self._get_canonical_alias()
        self.assertEqual(data["content"]["alias"], self.test_alias)
        self.assertEqual(
            data["content"]["alt_aliases"], [self.test_alias, other_test_alias]
        )

        # Delete the second alias.
        self.get_success(
            self.handler.delete_association(
                create_requester(self.admin_user), other_room_alias
            )
        )

        data = self._get_canonical_alias()
        self.assertEqual(data["content"]["alias"], self.test_alias)
        self.assertEqual(data["content"]["alt_aliases"], [self.test_alias])


class TestCreateAliasACL(unittest.HomeserverTestCase):
    user_id = "@test:test"

    servlets = [directory.register_servlets, room.register_servlets]

    def default_config(self) -> Dict[str, Any]:
        config = super().default_config()

        # Add custom alias creation rules to the config.
        config["alias_creation_rules"] = [
            {"user_id": "*", "alias": "#unofficial_*", "action": "allow"}
        ]

        return config

    def test_denied(self) -> None:
        room_id = self.helper.create_room_as(self.user_id)

        channel = self.make_request(
            "PUT",
            b"directory/room/%23test%3Atest",
            {"room_id": room_id},
        )
        self.assertEqual(403, channel.code, channel.result)

    def test_allowed(self) -> None:
        room_id = self.helper.create_room_as(self.user_id)

        channel = self.make_request(
            "PUT",
            b"directory/room/%23unofficial_test%3Atest",
            {"room_id": room_id},
        )
        self.assertEqual(200, channel.code, channel.result)

    def test_denied_during_creation(self) -> None:
        """A room alias that is not allowed should be rejected during creation."""
        # Invalid room alias.
        self.helper.create_room_as(
            self.user_id,
            expect_code=403,
            extra_content={"room_alias_name": "foo"},
        )

    def test_allowed_during_creation(self) -> None:
        """A valid room alias should be allowed during creation."""
        room_id = self.helper.create_room_as(
            self.user_id,
            extra_content={"room_alias_name": "unofficial_test"},
        )

        channel = self.make_request(
            "GET",
            b"directory/room/%23unofficial_test%3Atest",
        )
        self.assertEqual(200, channel.code, channel.result)
        self.assertEqual(channel.json_body["room_id"], room_id)


class TestCreatePublishedRoomACL(unittest.HomeserverTestCase):
    servlets = [
        synapse.rest.admin.register_servlets_for_client_rest_resource,
        login.register_servlets,
        directory.register_servlets,
        room.register_servlets,
    ]
    hijack_auth = False

    data = {"room_alias_name": "unofficial_test"}
    allowed_localpart = "allowed"

    def default_config(self) -> Dict[str, Any]:
        config = super().default_config()

        # Add custom room list publication rules to the config.
        config["room_list_publication_rules"] = [
            {
                "user_id": "@" + self.allowed_localpart + "*",
                "alias": "#unofficial_*",
                "action": "allow",
            },
            {"user_id": "*", "alias": "*", "action": "deny"},
        ]

        return config

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self.allowed_user_id = self.register_user(self.allowed_localpart, "pass")
        self.allowed_access_token = self.login(self.allowed_localpart, "pass")

        self.denied_user_id = self.register_user("denied", "pass")
        self.denied_access_token = self.login("denied", "pass")

    def test_denied_without_publication_permission(self) -> None:
        """
        Try to create a room, register an alias for it, and publish it,
        as a user without permission to publish rooms.
        (This is used as both a standalone test & as a helper function.)
        """
        self.helper.create_room_as(
            self.denied_user_id,
            tok=self.denied_access_token,
            extra_content=self.data,
            is_public=True,
            expect_code=403,
        )

    def test_allowed_when_creating_private_room(self) -> None:
        """
        Try to create a room, register an alias for it, and NOT publish it,
        as a user without permission to publish rooms.
        (This is used as both a standalone test & as a helper function.)
        """
        self.helper.create_room_as(
            self.denied_user_id,
            tok=self.denied_access_token,
            extra_content=self.data,
            is_public=False,
            expect_code=200,
        )

    def test_allowed_with_publication_permission(self) -> None:
        """
        Try to create a room, register an alias for it, and publish it,
        as a user WITH permission to publish rooms.
        (This is used as both a standalone test & as a helper function.)
        """
        self.helper.create_room_as(
            self.allowed_user_id,
            tok=self.allowed_access_token,
            extra_content=self.data,
            is_public=True,
            expect_code=200,
        )

    def test_denied_publication_with_invalid_alias(self) -> None:
        """
        Try to create a room, register an alias for it, and publish it,
        as a user WITH permission to publish rooms.
        """
        self.helper.create_room_as(
            self.allowed_user_id,
            tok=self.allowed_access_token,
            extra_content={"room_alias_name": "foo"},
            is_public=True,
            expect_code=403,
        )

    def test_can_create_as_private_room_after_rejection(self) -> None:
        """
        After failing to publish a room with an alias as a user without publish permission,
        retry as the same user, but without publishing the room.

        This should pass, but used to fail because the alias was registered by the first
        request, even though the room creation was denied.
        """
        self.test_denied_without_publication_permission()
        self.test_allowed_when_creating_private_room()

    def test_can_create_with_permission_after_rejection(self) -> None:
        """
        After failing to publish a room with an alias as a user without publish permission,
        retry as someone with permission, using the same alias.

        This also used to fail because of the alias having been registered by the first
        request, leaving it unavailable for any other user's new rooms.
        """
        self.test_denied_without_publication_permission()
        self.test_allowed_with_publication_permission()


class TestRoomListSearchDisabled(unittest.HomeserverTestCase):
    user_id = "@test:test"

    servlets = [directory.register_servlets, room.register_servlets]

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        room_id = self.helper.create_room_as(self.user_id)

        channel = self.make_request(
            "PUT", b"directory/list/room/%s" % (room_id.encode("ascii"),), b"{}"
        )
        self.assertEqual(200, channel.code, channel.result)

        self.room_list_handler = hs.get_room_list_handler()
        self.directory_handler = hs.get_directory_handler()

    def test_disabling_room_list(self) -> None:
        self.room_list_handler.enable_room_list_search = True
        self.directory_handler.enable_room_list_search = True

        # Room list is enabled so we should get some results
        channel = self.make_request("GET", b"publicRooms")
        self.assertEqual(200, channel.code, channel.result)
        self.assertTrue(len(channel.json_body["chunk"]) > 0)

        self.room_list_handler.enable_room_list_search = False
        self.directory_handler.enable_room_list_search = False

        # Room list disabled so we should get no results
        channel = self.make_request("GET", b"publicRooms")
        self.assertEqual(200, channel.code, channel.result)
        self.assertTrue(len(channel.json_body["chunk"]) == 0)

        # Room list disabled so we shouldn't be allowed to publish rooms
        room_id = self.helper.create_room_as(self.user_id)
        channel = self.make_request(
            "PUT", b"directory/list/room/%s" % (room_id.encode("ascii"),), b"{}"
        )
        self.assertEqual(403, channel.code, channel.result)
