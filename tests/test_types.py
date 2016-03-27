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

from tests import unittest

from synapse.api.errors import SynapseError
from synapse.server import HomeServer
from synapse.types import UserID, RoomAlias

mock_homeserver = HomeServer(hostname="my.domain")


class UserIDTestCase(unittest.TestCase):
    def test_parse(self):
        user = UserID.from_string("@1234abcd:my.domain")

        self.assertEquals("1234abcd", user.localpart)
        self.assertEquals("my.domain", user.domain)
        self.assertEquals(True, mock_homeserver.is_mine(user))

    def test_pase_empty(self):
        with self.assertRaises(SynapseError):
            UserID.from_string("")

    def test_build(self):
        user = UserID("5678efgh", "my.domain")

        self.assertEquals(user.to_string(), "@5678efgh:my.domain")

    def test_compare(self):
        userA = UserID.from_string("@userA:my.domain")
        userAagain = UserID.from_string("@userA:my.domain")
        userB = UserID.from_string("@userB:my.domain")

        self.assertTrue(userA == userAagain)
        self.assertTrue(userA != userB)


class RoomAliasTestCase(unittest.TestCase):
    def test_parse(self):
        room = RoomAlias.from_string("#channel:my.domain")

        self.assertEquals("channel", room.localpart)
        self.assertEquals("my.domain", room.domain)
        self.assertEquals(True, mock_homeserver.is_mine(room))

    def test_build(self):
        room = RoomAlias("channel", "my.domain")

        self.assertEquals(room.to_string(), "#channel:my.domain")
