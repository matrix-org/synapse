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

from synapse.server import HomeServer
from synapse.storage.room import RoomStore

from tests.utils import SQLiteMemoryDbPool


class RoomStoreTestCase(unittest.TestCase):

    @defer.inlineCallbacks
    def setUp(self):
        db_pool = SQLiteMemoryDbPool()
        yield db_pool.prepare()

        hs = HomeServer("test",
            db_pool=db_pool,
        )

        self.store = RoomStore(hs)

        self.room = hs.parse_roomid("!abcde:test")
        self.u_creator = hs.parse_userid("@creator:test")

    @defer.inlineCallbacks
    def test_store_room(self):
        yield self.store.store_room(self.room.to_string(),
            room_creator_user_id=self.u_creator.to_string(),
            is_public=True
        )

        room = yield self.store.get_room(self.room.to_string())

        self.assertEquals(self.room.to_string(), room.room_id)
        self.assertEquals(self.u_creator.to_string(), room.creator)
        self.assertTrue(room.is_public)
