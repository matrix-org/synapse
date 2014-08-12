import unittest

from synapse.server import BaseHomeServer
from synapse.types import UserID, RoomAlias

mock_homeserver = BaseHomeServer(hostname="my.domain")

class UserIDTestCase(unittest.TestCase):

    def test_parse(self):
        user = UserID.from_string("@1234abcd:my.domain", hs=mock_homeserver)

        self.assertEquals("1234abcd", user.localpart)
        self.assertEquals("my.domain", user.domain)
        self.assertEquals(True, user.is_mine)

    def test_build(self):
        user = UserID("5678efgh", "my.domain", True)

        self.assertEquals(user.to_string(), "@5678efgh:my.domain")

    def test_compare(self):
        userA = UserID.from_string("@userA:my.domain", hs=mock_homeserver)
        userAagain = UserID.from_string("@userA:my.domain", hs=mock_homeserver)
        userB = UserID.from_string("@userB:my.domain", hs=mock_homeserver)

        self.assertTrue(userA == userAagain)
        self.assertTrue(userA != userB)

    def test_via_homeserver(self):
        user = mock_homeserver.parse_userid("@3456ijkl:my.domain")

        self.assertEquals("3456ijkl", user.localpart)
        self.assertEquals("my.domain", user.domain)


class RoomAliasTestCase(unittest.TestCase):

    def test_parse(self):
        room = RoomAlias.from_string("#channel:my.domain", hs=mock_homeserver)

        self.assertEquals("channel", room.localpart)
        self.assertEquals("my.domain", room.domain)
        self.assertEquals(True, room.is_mine)

    def test_build(self):
        room = RoomAlias("channel", "my.domain", True)

        self.assertEquals(room.to_string(), "#channel:my.domain")
