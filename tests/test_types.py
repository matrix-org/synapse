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

from synapse.api.errors import SynapseError
from synapse.types import (
    RoomAlias,
    UserID,
    get_domain_from_id,
    get_localpart_from_id,
    map_username_to_mxid_localpart,
)

from tests import unittest


class IsMineIDTests(unittest.HomeserverTestCase):
    def test_is_mine_id(self) -> None:
        self.assertTrue(self.hs.is_mine_id("@user:test"))
        self.assertTrue(self.hs.is_mine_id("#room:test"))
        self.assertTrue(self.hs.is_mine_id("invalid:test"))

        self.assertFalse(self.hs.is_mine_id("@user:test\0"))
        self.assertFalse(self.hs.is_mine_id("@user"))

    def test_two_colons(self) -> None:
        """Test handling of IDs containing more than one colon."""
        # The domain starts after the first colon.
        # These functions must interpret things consistently.
        self.assertFalse(self.hs.is_mine_id("@user:test:test"))
        self.assertEqual("user", get_localpart_from_id("@user:test:test"))
        self.assertEqual("test:test", get_domain_from_id("@user:test:test"))


class UserIDTestCase(unittest.HomeserverTestCase):
    def test_parse(self):
        user = UserID.from_string("@1234abcd:test")

        self.assertEqual("1234abcd", user.localpart)
        self.assertEqual("test", user.domain)
        self.assertEqual(True, self.hs.is_mine(user))

    def test_parse_rejects_empty_id(self):
        with self.assertRaises(SynapseError):
            UserID.from_string("")

    def test_parse_rejects_missing_sigil(self):
        with self.assertRaises(SynapseError):
            UserID.from_string("alice:example.com")

    def test_parse_rejects_missing_separator(self):
        with self.assertRaises(SynapseError):
            UserID.from_string("@alice.example.com")

    def test_validation_rejects_missing_domain(self):
        self.assertFalse(UserID.is_valid("@alice:"))

    def test_build(self):
        user = UserID("5678efgh", "my.domain")

        self.assertEqual(user.to_string(), "@5678efgh:my.domain")

    def test_compare(self):
        userA = UserID.from_string("@userA:my.domain")
        userAagain = UserID.from_string("@userA:my.domain")
        userB = UserID.from_string("@userB:my.domain")

        self.assertTrue(userA == userAagain)
        self.assertTrue(userA != userB)


class RoomAliasTestCase(unittest.HomeserverTestCase):
    def test_parse(self):
        room = RoomAlias.from_string("#channel:test")

        self.assertEqual("channel", room.localpart)
        self.assertEqual("test", room.domain)
        self.assertEqual(True, self.hs.is_mine(room))

    def test_build(self):
        room = RoomAlias("channel", "my.domain")

        self.assertEqual(room.to_string(), "#channel:my.domain")

    def test_validate(self):
        id_string = "#test:domain,test"
        self.assertFalse(RoomAlias.is_valid(id_string))


class MapUsernameTestCase(unittest.TestCase):
    def testPassThrough(self):
        self.assertEqual(map_username_to_mxid_localpart("test1234"), "test1234")

    def testUpperCase(self):
        self.assertEqual(map_username_to_mxid_localpart("tEST_1234"), "test_1234")
        self.assertEqual(
            map_username_to_mxid_localpart("tEST_1234", case_sensitive=True),
            "t_e_s_t__1234",
        )

    def testSymbols(self):
        self.assertEqual(
            map_username_to_mxid_localpart("test=$?_1234"), "test=3d=24=3f_1234"
        )

    def testLeadingUnderscore(self):
        self.assertEqual(map_username_to_mxid_localpart("_test_1234"), "=5ftest_1234")

    def testNonAscii(self):
        # this should work with either a unicode or a bytes
        self.assertEqual(map_username_to_mxid_localpart("têst"), "t=c3=aast")
        self.assertEqual(map_username_to_mxid_localpart("têst".encode()), "t=c3=aast")
