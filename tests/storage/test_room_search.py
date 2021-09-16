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
from synapse.rest.client import login, room

from tests.unittest import HomeserverTestCase


class NullByteInsertionTest(HomeserverTestCase):
    servlets = [
        synapse.rest.admin.register_servlets_for_client_rest_resource,
        login.register_servlets,
        room.register_servlets,
    ]

    def test_null_byte(self):
        """
        Postgres doesn't like null bytes going into the search tables. Internally
        we replace those with a space.

        Ensure this doesn't break anything.
        """

        # register a user and create a room, creat some messages
        self.register_user("alice", "password")
        access_token = self.login("alice", "password")
        room_id = self.helper.create_room_as("alice", True, "1", access_token)
        body1 = "hi\u0000bob"
        body2 = "another message"
        body3 = "hi alice"

        # send messages and ensure they don't cause an internal server
        # error
        resp1 = self.helper.send(room_id, body1, "1", access_token)
        resp2 = self.helper.send(room_id, body2, "2", access_token)
        resp3 = self.helper.send(room_id, body3, "3", access_token)
        self.assertTrue("event_id" in resp1)
        self.assertTrue("event_id" in resp2)
        self.assertTrue("event_id" in resp3)

        # check that search still works with the message where the null byte was replaced
        store = self.hs.get_datastore()
        res1 = self.get_success(
            store.search_msgs([room_id], "hi bob", ["content.body"])
        )
        self.assertEquals(res1.get("count"), 1)
        self.assertIn("bob", res1.get("highlights"))
        self.assertIn("hi", res1.get("highlights"))

        # check that search still works with another unrelated message
        res2 = self.get_success(
            store.search_msgs([room_id], "another", ["content.body"])
        )
        self.assertEquals(res2.get("count"), 1)
        self.assertIn("another", res2.get("highlights"))

        # check that search still works when given a search term that overlaps
        # with the message that we replaced the null byte in and an unrelated one
        res3 = self.get_success(store.search_msgs([room_id], "hi", ["content.body"]))
        self.assertEquals(res3.get("count"), 2)
        res4 = self.get_success(
            store.search_msgs([room_id], "hi alice", ["content.body"])
        )
        self.assertIn("alice", res4.get("highlights"))
