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


from twisted.internet import defer

from synapse.types import RoomAlias, RoomID

from tests import unittest
from tests.utils import setup_test_homeserver


class DirectoryStoreTestCase(unittest.TestCase):
    @defer.inlineCallbacks
    def setUp(self):
        hs = yield setup_test_homeserver(self.addCleanup)

        self.store = hs.get_datastore()

        self.room = RoomID.from_string("!abcde:test")
        self.alias = RoomAlias.from_string("#my-room:test")

    @defer.inlineCallbacks
    def test_room_to_alias(self):
        yield defer.ensureDeferred(
            self.store.create_room_alias_association(
                room_alias=self.alias, room_id=self.room.to_string(), servers=["test"]
            )
        )

        self.assertEquals(
            ["#my-room:test"],
            (
                yield defer.ensureDeferred(
                    self.store.get_aliases_for_room(self.room.to_string())
                )
            ),
        )

    @defer.inlineCallbacks
    def test_alias_to_room(self):
        yield defer.ensureDeferred(
            self.store.create_room_alias_association(
                room_alias=self.alias, room_id=self.room.to_string(), servers=["test"]
            )
        )

        self.assertObjectHasAttributes(
            {"room_id": self.room.to_string(), "servers": ["test"]},
            (
                yield defer.ensureDeferred(
                    self.store.get_association_from_room_alias(self.alias)
                )
            ),
        )

    @defer.inlineCallbacks
    def test_delete_alias(self):
        yield defer.ensureDeferred(
            self.store.create_room_alias_association(
                room_alias=self.alias, room_id=self.room.to_string(), servers=["test"]
            )
        )

        room_id = yield defer.ensureDeferred(self.store.delete_room_alias(self.alias))
        self.assertEqual(self.room.to_string(), room_id)

        self.assertIsNone(
            (
                yield defer.ensureDeferred(
                    self.store.get_association_from_room_alias(self.alias)
                )
            )
        )
