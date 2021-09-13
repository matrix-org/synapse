import synapse.rest.admin
from synapse.rest.client import account, login, register, room

from tests.unittest import HomeserverTestCase


class NullByteInsertionTest(HomeserverTestCase):
    servlets = [
        synapse.rest.admin.register_servlets_for_client_rest_resource,
        login.register_servlets,
        account.register_servlets,
        register.register_servlets,
        room.register_servlets,
    ]

    def setUp(self):
        super().setUp()

    # Note that this test must be run with postgres or else is meaningless,
    # as sqlite will accept insertion of null code points
    def test_null_byte(self):
        self.register_user("alice", "password")
        access_token = self.login("alice", "password")
        room_id = self.helper.create_room_as("alice", True, "1", access_token)
        body = '{"body":"\u0000", "msgtype":"m.text"}'

        resp = self.helper.send(room_id, body, "1", access_token)
        self.assertTrue("event_id" in resp)
