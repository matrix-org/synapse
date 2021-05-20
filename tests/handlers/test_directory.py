# -*- coding: utf-8 -*-
# Copyright 2014-2016 OpenMarket Ltd
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


from mock import Mock

import synapse
import synapse.api.errors
from synapse.api.constants import EventTypes
from synapse.appservice import ApplicationService
from synapse.config.room_directory import RoomDirectoryConfig
from synapse.rest import admin
from synapse.rest.client.v1 import directory, login, room
from synapse.types import RoomAlias, create_requester

from tests import unittest
from tests.test_utils import make_awaitable


class DirectoryTestCase(unittest.HomeserverTestCase):
    """ Tests the directory service. """

    def make_homeserver(self, reactor, clock):
        self.mock_federation = Mock()
        self.mock_registry = Mock()

        self.query_handlers = {}

        def register_query_handler(query_type, handler):
            self.query_handlers[query_type] = handler

        self.mock_registry.register_query_handler = register_query_handler

        hs = self.setup_test_homeserver(
            federation_client=self.mock_federation,
            federation_registry=self.mock_registry,
        )

        self.handler = hs.get_directory_handler()

        self.store = hs.get_datastore()

        self.my_room = RoomAlias.from_string("#my-room:test")
        self.your_room = RoomAlias.from_string("#your-room:test")
        self.remote_room = RoomAlias.from_string("#another:remote")

        return hs

    def test_get_local_association(self):
        self.get_success(
            self.store.create_room_alias_association(
                self.my_room, "!8765qwer:test", ["test"]
            )
        )

        result = self.get_success(self.handler.get_association(self.my_room))

        self.assertEquals({"room_id": "!8765qwer:test", "servers": ["test"]}, result)

    def test_get_remote_association(self):
        self.mock_federation.make_query.return_value = make_awaitable(
            {"room_id": "!8765qwer:test", "servers": ["test", "remote"]}
        )

        result = self.get_success(self.handler.get_association(self.remote_room))

        self.assertEquals(
            {"room_id": "!8765qwer:test", "servers": ["test", "remote"]}, result
        )
        self.mock_federation.make_query.assert_called_with(
            destination="remote",
            query_type="directory",
            args={"room_alias": "#another:remote"},
            retry_on_dns_fail=False,
            ignore_backoff=True,
        )

    def test_incoming_fed_query(self):
        self.get_success(
            self.store.create_room_alias_association(
                self.your_room, "!8765asdf:test", ["test"]
            )
        )

        response = self.get_success(
            self.handler.on_directory_query({"room_alias": "#your-room:test"})
        )

        self.assertEquals({"room_id": "!8765asdf:test", "servers": ["test"]}, response)


class TestCreateAlias(unittest.HomeserverTestCase):
    servlets = [
        synapse.rest.admin.register_servlets,
        login.register_servlets,
        room.register_servlets,
        directory.register_servlets,
    ]

    def prepare(self, reactor, clock, hs):
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

    def test_create_alias_joined_room(self):
        """A user can create an alias for a room they're in."""
        self.get_success(
            self.handler.create_association(
                create_requester(self.test_user),
                self.room_alias,
                self.room_id,
            )
        )

    def test_create_alias_other_room(self):
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

    def test_create_alias_admin(self):
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

    def prepare(self, reactor, clock, hs):
        self.store = hs.get_datastore()
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

    def _create_alias(self, user):
        # Create a new alias to this room.
        self.get_success(
            self.store.create_room_alias_association(
                self.room_alias, self.room_id, ["test"], user
            )
        )

    def test_delete_alias_not_allowed(self):
        """A user that doesn't meet the expected guidelines cannot delete an alias."""
        self._create_alias(self.admin_user)
        self.get_failure(
            self.handler.delete_association(
                create_requester(self.test_user), self.room_alias
            ),
            synapse.api.errors.AuthError,
        )

    def test_delete_alias_creator(self):
        """An alias creator can delete their own alias."""
        # Create an alias from a different user.
        self._create_alias(self.test_user)

        # Delete the user's alias.
        result = self.get_success(
            self.handler.delete_association(
                create_requester(self.test_user), self.room_alias
            )
        )
        self.assertEquals(self.room_id, result)

        # Confirm the alias is gone.
        self.get_failure(
            self.handler.get_association(self.room_alias),
            synapse.api.errors.SynapseError,
        )

    def test_delete_alias_admin(self):
        """A server admin can delete an alias created by another user."""
        # Create an alias from a different user.
        self._create_alias(self.test_user)

        # Delete the user's alias as the admin.
        result = self.get_success(
            self.handler.delete_association(
                create_requester(self.admin_user), self.room_alias
            )
        )
        self.assertEquals(self.room_id, result)

        # Confirm the alias is gone.
        self.get_failure(
            self.handler.get_association(self.room_alias),
            synapse.api.errors.SynapseError,
        )

    def test_delete_alias_sufficient_power(self):
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
        self.assertEquals(self.room_id, result)

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

    def prepare(self, reactor, clock, hs):
        self.store = hs.get_datastore()
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

    def _set_canonical_alias(self, content):
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
            self.state_handler.get_current_state(
                self.room_id, EventTypes.CanonicalAlias, ""
            )
        )

    def test_remove_alias(self):
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

    def test_remove_other_alias(self):
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

    def prepare(self, reactor, clock, hs):
        # We cheekily override the config to add custom alias creation rules
        config = {}
        config["alias_creation_rules"] = [
            {"user_id": "*", "alias": "#unofficial_*", "action": "allow"}
        ]
        config["room_list_publication_rules"] = []

        rd_config = RoomDirectoryConfig()
        rd_config.read_config(config)

        self.hs.config.is_alias_creation_allowed = rd_config.is_alias_creation_allowed

        return hs

    def test_denied(self):
        room_id = self.helper.create_room_as(self.user_id)

        channel = self.make_request(
            "PUT",
            b"directory/room/%23test%3Atest",
            ('{"room_id":"%s"}' % (room_id,)).encode("ascii"),
        )
        self.assertEquals(403, channel.code, channel.result)

    def test_allowed(self):
        room_id = self.helper.create_room_as(self.user_id)

        channel = self.make_request(
            "PUT",
            b"directory/room/%23unofficial_test%3Atest",
            ('{"room_id":"%s"}' % (room_id,)).encode("ascii"),
        )
        self.assertEquals(200, channel.code, channel.result)


class TestRoomListSearchDisabled(unittest.HomeserverTestCase):
    user_id = "@test:test"

    servlets = [directory.register_servlets, room.register_servlets]

    def prepare(self, reactor, clock, hs):
        room_id = self.helper.create_room_as(self.user_id)

        channel = self.make_request(
            "PUT", b"directory/list/room/%s" % (room_id.encode("ascii"),), b"{}"
        )
        self.assertEquals(200, channel.code, channel.result)

        self.room_list_handler = hs.get_room_list_handler()
        self.directory_handler = hs.get_directory_handler()

        return hs

    def test_disabling_room_list(self):
        self.room_list_handler.enable_room_list_search = True
        self.directory_handler.enable_room_list_search = True

        # Room list is enabled so we should get some results
        channel = self.make_request("GET", b"publicRooms")
        self.assertEquals(200, channel.code, channel.result)
        self.assertTrue(len(channel.json_body["chunk"]) > 0)

        self.room_list_handler.enable_room_list_search = False
        self.directory_handler.enable_room_list_search = False

        # Room list disabled so we should get no results
        channel = self.make_request("GET", b"publicRooms")
        self.assertEquals(200, channel.code, channel.result)
        self.assertTrue(len(channel.json_body["chunk"]) == 0)

        # Room list disabled so we shouldn't be allowed to publish rooms
        room_id = self.helper.create_room_as(self.user_id)
        channel = self.make_request(
            "PUT", b"directory/list/room/%s" % (room_id.encode("ascii"),), b"{}"
        )
        self.assertEquals(403, channel.code, channel.result)


class TestAppserviceRoomDirectoryList(unittest.HomeserverTestCase):

    servlets = [
        admin.register_servlets_for_client_rest_resource,
        directory.register_servlets,
        login.register_servlets,
        room.register_servlets,
    ]

    def prepare(self, reactor, clock, homeserver):
        # Create a fake appservice
        self.as_token = "i_am_an_app_service"

        appservice = ApplicationService(
            self.as_token,
            self.hs.config.server_name,
            id="1234",
            namespaces={"users": [{"regex": r"@as_user.*", "exclusive": True}]},
            sender="@as:test",
        )
        self.hs.get_datastore().services_cache.append(appservice)

        # Create a user and a room
        self.room_owner = self.register_user("room_owner", "test")
        self.room_owner_tok = self.login("room_owner", "test")

        self.room_id = self.helper.create_room_as(
            self.room_owner, tok=self.room_owner_tok
        )

        # Create another user to poll the room directory with
        self.user = self.register_user("user", "test")
        self.user_tok = self.login("user", "test")

        # Create a server admin to attempt delisting rooms
        self.admin_user = self.register_user("admin", "test", admin=True)
        self.admin_tok = self.login("admin", "test")

    def test_normal_user_cannot_edit_appservice_room_directory(self):
        """Tests that a normal user (not an appservice) cannot edit the appservice-specific
        room directory.
        """
        # Attempt to list the room as a normal user
        self._set_visibility_of_appservice_room(
            self.room_id,
            visible=True,
            access_token=self.user_tok,
            expect_code=403,
        )

        # Attempt to delist the room as a normal user
        self._set_visibility_of_appservice_room(
            self.room_id,
            visible=False,
            access_token=self.user_tok,
            expect_code=403,
        )

    def test_add_and_remove_from_appservice_room_directory(self):
        """Tests that we can add and remove rooms from the appservice-specific
        room directory.
        """
        # Check that the room is not currently in the public room directory
        self.assertFalse(self._is_room_in_public_room_directory(self.room_id))

        # Attempt to list the room as an appservice
        self._set_visibility_of_appservice_room(
            self.room_id,
            visible=True,
        )

        # Check that the room is currently in the public room directory
        self.assertTrue(self._is_room_in_public_room_directory(self.room_id))

        # Attempt to remove the room as an appservice
        self._set_visibility_of_appservice_room(
            self.room_id,
            visible=False,
        )

        # Check that the room is no longer in the public room directory
        self.assertFalse(self._is_room_in_public_room_directory(self.room_id))

    def _set_visibility_of_appservice_room(
        self,
        room_id: str,
        visible: bool,
        access_token: str = None,
        expect_code: int = 200,
    ):
        """Adds or removes a room from the appservice room list.

        Args:
            room_id: The ID of the room.
            visible: True to list the room, False to delist it.
            access_token: The access token to use for the request. If None,
                self.as_token is used.
            expect_code: The expected HTTP status code in the response. If None,
                will expect 200 OK.
        """
        # Allow modifying the token used
        if not access_token:
            access_token = self.as_token

        # Build the directory room list URL
        network_id = "some_network"
        url = f"/_matrix/client/api/v1/directory/list/appservice/{network_id}/{room_id}"

        if visible:
            # List the room
            channel = self.make_request(
                "PUT",
                url,
                {"visibility": "public"},
                access_token=access_token,
                shorthand=False,
            )
            self.assertEquals(channel.code, expect_code, channel.json_body)
        else:
            # Delist the room
            channel = self.make_request(
                "DELETE",
                url,
                access_token=access_token,
                shorthand=False,
            )
            self.assertEquals(channel.code, expect_code, channel.json_body)

    def _is_room_in_public_room_directory(self, room_id: str) -> bool:
        """Return True or False if a given room_id is currently listed in the
        public room directory.

        Sets "include_all_networks": True in the request so that appservice
        rooms appear as well.

        Args:
            room_id: The room ID to check the public room directory for.

        Returns:
            True or False if the room is in the public room list.
        """
        channel = self.make_request(
            "POST",
            "publicRooms",
            # We need to make sure to specify 'include_all_networks', or our specific network,
            # in order for the room to appear.
            {
                "include_all_networks": True,
            },
            access_token=self.user_tok,
        )
        self.assertEquals(200, channel.code, channel.result)

        # Pull out the returned public rooms
        public_room_chunks = channel.json_body["chunk"]

        # Check that we found our listed room
        found_room = False
        for room_chunk in public_room_chunks:
            if room_chunk["room_id"] == room_id:
                found_room = True

        # Return whether we found the room
        return found_room
