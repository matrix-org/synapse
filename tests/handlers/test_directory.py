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

from twisted.internet import defer

import synapse.api.errors
from synapse.config.room_directory import RoomDirectoryConfig
from synapse.rest.client.v1 import directory, room
from synapse.types import RoomAlias, create_requester

from tests import unittest


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
            http_client=None,
            resource_for_federation=Mock(),
            federation_client=self.mock_federation,
            federation_registry=self.mock_registry,
        )

        self.handler = hs.get_handlers().directory_handler

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
        self.mock_federation.make_query.return_value = defer.succeed(
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

    def test_delete_alias_not_allowed(self):
        room_id = "!8765qwer:test"
        self.get_success(
            self.store.create_room_alias_association(self.my_room, room_id, ["test"])
        )

        self.get_failure(
            self.handler.delete_association(
                create_requester("@user:test"), self.my_room
            ),
            synapse.api.errors.AuthError,
        )

    def test_delete_alias(self):
        room_id = "!8765qwer:test"
        user_id = "@user:test"
        self.get_success(
            self.store.create_room_alias_association(
                self.my_room, room_id, ["test"], user_id
            )
        )

        result = self.get_success(
            self.handler.delete_association(create_requester(user_id), self.my_room)
        )
        self.assertEquals(room_id, result)

        # The alias should not be found.
        self.get_failure(
            self.handler.get_association(self.my_room), synapse.api.errors.SynapseError
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

        request, channel = self.make_request(
            "PUT",
            b"directory/room/%23test%3Atest",
            ('{"room_id":"%s"}' % (room_id,)).encode("ascii"),
        )
        self.render(request)
        self.assertEquals(403, channel.code, channel.result)

    def test_allowed(self):
        room_id = self.helper.create_room_as(self.user_id)

        request, channel = self.make_request(
            "PUT",
            b"directory/room/%23unofficial_test%3Atest",
            ('{"room_id":"%s"}' % (room_id,)).encode("ascii"),
        )
        self.render(request)
        self.assertEquals(200, channel.code, channel.result)


class TestRoomListSearchDisabled(unittest.HomeserverTestCase):
    user_id = "@test:test"

    servlets = [directory.register_servlets, room.register_servlets]

    def prepare(self, reactor, clock, hs):
        room_id = self.helper.create_room_as(self.user_id)

        request, channel = self.make_request(
            "PUT", b"directory/list/room/%s" % (room_id.encode("ascii"),), b"{}"
        )
        self.render(request)
        self.assertEquals(200, channel.code, channel.result)

        self.room_list_handler = hs.get_room_list_handler()
        self.directory_handler = hs.get_handlers().directory_handler

        return hs

    def test_disabling_room_list(self):
        self.room_list_handler.enable_room_list_search = True
        self.directory_handler.enable_room_list_search = True

        # Room list is enabled so we should get some results
        request, channel = self.make_request("GET", b"publicRooms")
        self.render(request)
        self.assertEquals(200, channel.code, channel.result)
        self.assertTrue(len(channel.json_body["chunk"]) > 0)

        self.room_list_handler.enable_room_list_search = False
        self.directory_handler.enable_room_list_search = False

        # Room list disabled so we should get no results
        request, channel = self.make_request("GET", b"publicRooms")
        self.render(request)
        self.assertEquals(200, channel.code, channel.result)
        self.assertTrue(len(channel.json_body["chunk"]) == 0)

        # Room list disabled so we shouldn't be allowed to publish rooms
        room_id = self.helper.create_room_as(self.user_id)
        request, channel = self.make_request(
            "PUT", b"directory/list/room/%s" % (room_id.encode("ascii"),), b"{}"
        )
        self.render(request)
        self.assertEquals(403, channel.code, channel.result)
