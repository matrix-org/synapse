# -*- coding: utf-8 -*-
# Copyright 2014 OpenMarket Ltd
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


from tests import unittest
from twisted.internet import defer

from mock import Mock

from synapse.server import HomeServer
from synapse.http.client import MatrixHttpClient
from synapse.handlers.directory import DirectoryHandler
from synapse.storage.directory import RoomAliasMapping

from tests.utils import SQLiteMemoryDbPool


class DirectoryHandlers(object):
    def __init__(self, hs):
        self.directory_handler = DirectoryHandler(hs)


class DirectoryTestCase(unittest.TestCase):
    """ Tests the directory service. """

    @defer.inlineCallbacks
    def setUp(self):
        self.mock_federation = Mock(spec=[
            "make_query",
        ])

        self.query_handlers = {}
        def register_query_handler(query_type, handler):
            self.query_handlers[query_type] = handler
        self.mock_federation.register_query_handler = register_query_handler

        db_pool = SQLiteMemoryDbPool()
        yield db_pool.prepare()

        hs = HomeServer("test",
            db_pool=db_pool,
            http_client=None,
            resource_for_federation=Mock(),
            replication_layer=self.mock_federation,
        )
        hs.handlers = DirectoryHandlers(hs)

        self.handler = hs.get_handlers().directory_handler

        self.store = hs.get_datastore()

        self.my_room = hs.parse_roomalias("#my-room:test")
        self.your_room = hs.parse_roomalias("#your-room:test")
        self.remote_room = hs.parse_roomalias("#another:remote")

    @defer.inlineCallbacks
    def test_get_local_association(self):
        yield self.store.create_room_alias_association(
            self.my_room, "!8765qwer:test", ["test"]
        )

        result = yield self.handler.get_association(self.my_room)

        self.assertEquals({
            "room_id": "!8765qwer:test",
            "servers": ["test"],
        }, result)

    @defer.inlineCallbacks
    def test_get_remote_association(self):
        self.mock_federation.make_query.return_value = defer.succeed(
            {"room_id": "!8765qwer:test", "servers": ["test", "remote"]}
        )

        result = yield self.handler.get_association(self.remote_room)

        self.assertEquals({
            "room_id": "!8765qwer:test",
            "servers": ["test", "remote"],
        }, result)
        self.mock_federation.make_query.assert_called_with(
            destination="remote",
            query_type="directory",
            args={
                "room_alias": "#another:remote",
                MatrixHttpClient.RETRY_DNS_LOOKUP_FAILURES: False
            }
        )

    @defer.inlineCallbacks
    def test_incoming_fed_query(self):
        yield self.store.create_room_alias_association(
            self.your_room, "!8765asdf:test", ["test"]
        )

        response = yield self.query_handlers["directory"](
            {"room_alias": "#your-room:test"}
        )

        self.assertEquals({
            "room_id": "!8765asdf:test",
            "servers": ["test"],
        }, response)
