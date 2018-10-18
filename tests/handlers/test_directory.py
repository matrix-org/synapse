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

from synapse.config.room_directory import RoomDirectoryConfig
from synapse.handlers.directory import DirectoryHandler
from synapse.rest.client.v1 import directory, room
from synapse.types import RoomAlias

from tests import unittest
from tests.utils import setup_test_homeserver


class DirectoryHandlers(object):
    def __init__(self, hs):
        self.directory_handler = DirectoryHandler(hs)


class DirectoryTestCase(unittest.TestCase):
    """ Tests the directory service. """

    @defer.inlineCallbacks
    def setUp(self):
        self.mock_federation = Mock()
        self.mock_registry = Mock()

        self.query_handlers = {}

        def register_query_handler(query_type, handler):
            self.query_handlers[query_type] = handler

        self.mock_registry.register_query_handler = register_query_handler

        hs = yield setup_test_homeserver(
            self.addCleanup,
            http_client=None,
            resource_for_federation=Mock(),
            federation_client=self.mock_federation,
            federation_registry=self.mock_registry,
        )
        hs.handlers = DirectoryHandlers(hs)

        self.handler = hs.get_handlers().directory_handler

        self.store = hs.get_datastore()

        self.my_room = RoomAlias.from_string("#my-room:test")
        self.your_room = RoomAlias.from_string("#your-room:test")
        self.remote_room = RoomAlias.from_string("#another:remote")

    @defer.inlineCallbacks
    def test_get_local_association(self):
        yield self.store.create_room_alias_association(
            self.my_room, "!8765qwer:test", ["test"]
        )

        result = yield self.handler.get_association(self.my_room)

        self.assertEquals({"room_id": "!8765qwer:test", "servers": ["test"]}, result)

    @defer.inlineCallbacks
    def test_get_remote_association(self):
        self.mock_federation.make_query.return_value = defer.succeed(
            {"room_id": "!8765qwer:test", "servers": ["test", "remote"]}
        )

        result = yield self.handler.get_association(self.remote_room)

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

    @defer.inlineCallbacks
    def test_incoming_fed_query(self):
        yield self.store.create_room_alias_association(
            self.your_room, "!8765asdf:test", ["test"]
        )

        response = yield self.query_handlers["directory"](
            {"room_alias": "#your-room:test"}
        )

        self.assertEquals({"room_id": "!8765asdf:test", "servers": ["test"]}, response)


class TestCreateAliasACL(unittest.HomeserverTestCase):
    user_id = "@test:test"

    servlets = [directory.register_servlets, room.register_servlets]

    def prepare(self, hs, reactor, clock):
        # We cheekily override the config to add custom alias creation rules
        config = {}
        config["alias_creation_rules"] = [
            {
                "user_id": "*",
                "alias": "#unofficial_*",
                "action": "allowed",
            }
        ]

        rd_config = RoomDirectoryConfig()
        rd_config.read_config(config)

        self.hs.config.is_alias_creation_allowed = rd_config.is_alias_creation_allowed

        return hs

    def test_denied(self):
        room_id = self.helper.create_room_as(self.user_id)

        request, channel = self.make_request(
            "PUT",
            b"directory/room/%23test%3Atest",
            ('{"room_id":"%s"}' % (room_id,)).encode('ascii'),
        )
        self.render(request)
        self.assertEquals(403, channel.code, channel.result)

    def test_allowed(self):
        room_id = self.helper.create_room_as(self.user_id)

        request, channel = self.make_request(
            "PUT",
            b"directory/room/%23unofficial_test%3Atest",
            ('{"room_id":"%s"}' % (room_id,)).encode('ascii'),
        )
        self.render(request)
        self.assertEquals(200, channel.code, channel.result)
