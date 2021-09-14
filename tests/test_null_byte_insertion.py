# Copyright 2021 The Matrix.org Foundation C.I.C.
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
