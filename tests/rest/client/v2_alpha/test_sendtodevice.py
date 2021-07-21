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

from synapse.rest import admin
from synapse.rest.client.v1 import login
from synapse.rest.client.v2_alpha import sendtodevice, sync

from tests.unittest import HomeserverTestCase, override_config


class SendToDeviceTestCase(HomeserverTestCase):
    servlets = [
        admin.register_servlets,
        login.register_servlets,
        sendtodevice.register_servlets,
        sync.register_servlets,
    ]

    def test_user_to_user(self):
        """A to-device message from one user to another should get delivered"""

        user1 = self.register_user("u1", "pass")
        user1_tok = self.login("u1", "pass", "d1")

        user2 = self.register_user("u2", "pass")
        user2_tok = self.login("u2", "pass", "d2")

        # send the message
        test_msg = {"foo": "bar"}
        chan = self.make_request(
            "PUT",
            "/_matrix/client/r0/sendToDevice/m.test/1234",
            content={"messages": {user2: {"d2": test_msg}}},
            access_token=user1_tok,
        )
        self.assertEqual(chan.code, 200, chan.result)

        # check it appears
        channel = self.make_request("GET", "/sync", access_token=user2_tok)
        self.assertEqual(channel.code, 200, channel.result)
        expected_result = {
            "events": [
                {
                    "sender": user1,
                    "type": "m.test",
                    "content": test_msg,
                }
            ]
        }
        self.assertEqual(channel.json_body["to_device"], expected_result)

        # it should re-appear if we do another sync
        channel = self.make_request("GET", "/sync", access_token=user2_tok)
        self.assertEqual(channel.code, 200, channel.result)
        self.assertEqual(channel.json_body["to_device"], expected_result)

        # it should *not* appear if we do an incremental sync
        sync_token = channel.json_body["next_batch"]
        channel = self.make_request(
            "GET", f"/sync?since={sync_token}", access_token=user2_tok
        )
        self.assertEqual(channel.code, 200, channel.result)
        self.assertEqual(channel.json_body.get("to_device", {}).get("events", []), [])

    @override_config({"rc_key_requests": {"per_second": 10, "burst_count": 2}})
    def test_local_room_key_request(self):
        """m.room_key_request has special-casing; test from local user"""
        user1 = self.register_user("u1", "pass")
        user1_tok = self.login("u1", "pass", "d1")

        user2 = self.register_user("u2", "pass")
        user2_tok = self.login("u2", "pass", "d2")

        # send three messages
        for i in range(3):
            chan = self.make_request(
                "PUT",
                f"/_matrix/client/r0/sendToDevice/m.room_key_request/{i}",
                content={"messages": {user2: {"d2": {"idx": i}}}},
                access_token=user1_tok,
            )
            self.assertEqual(chan.code, 200, chan.result)

        # now sync: we should get two of the three
        channel = self.make_request("GET", "/sync", access_token=user2_tok)
        self.assertEqual(channel.code, 200, channel.result)
        msgs = channel.json_body["to_device"]["events"]
        self.assertEqual(len(msgs), 2)
        for i in range(2):
            self.assertEqual(
                msgs[i],
                {"sender": user1, "type": "m.room_key_request", "content": {"idx": i}},
            )
        sync_token = channel.json_body["next_batch"]

        # ... time passes
        self.reactor.advance(1)

        # and we can send more messages
        chan = self.make_request(
            "PUT",
            "/_matrix/client/r0/sendToDevice/m.room_key_request/3",
            content={"messages": {user2: {"d2": {"idx": 3}}}},
            access_token=user1_tok,
        )
        self.assertEqual(chan.code, 200, chan.result)

        # ... which should arrive
        channel = self.make_request(
            "GET", f"/sync?since={sync_token}", access_token=user2_tok
        )
        self.assertEqual(channel.code, 200, channel.result)
        msgs = channel.json_body["to_device"]["events"]
        self.assertEqual(len(msgs), 1)
        self.assertEqual(
            msgs[0],
            {"sender": user1, "type": "m.room_key_request", "content": {"idx": 3}},
        )

    @override_config({"rc_key_requests": {"per_second": 10, "burst_count": 2}})
    def test_remote_room_key_request(self):
        """m.room_key_request has special-casing; test from remote user"""
        user2 = self.register_user("u2", "pass")
        user2_tok = self.login("u2", "pass", "d2")

        federation_registry = self.hs.get_federation_registry()

        # send three messages
        for i in range(3):
            self.get_success(
                federation_registry.on_edu(
                    "m.direct_to_device",
                    "remote_server",
                    {
                        "sender": "@user:remote_server",
                        "type": "m.room_key_request",
                        "messages": {user2: {"d2": {"idx": i}}},
                        "message_id": f"{i}",
                    },
                )
            )

        # now sync: we should get two of the three
        channel = self.make_request("GET", "/sync", access_token=user2_tok)
        self.assertEqual(channel.code, 200, channel.result)
        msgs = channel.json_body["to_device"]["events"]
        self.assertEqual(len(msgs), 2)
        for i in range(2):
            self.assertEqual(
                msgs[i],
                {
                    "sender": "@user:remote_server",
                    "type": "m.room_key_request",
                    "content": {"idx": i},
                },
            )
        sync_token = channel.json_body["next_batch"]

        # ... time passes
        self.reactor.advance(1)

        # and we can send more messages
        self.get_success(
            federation_registry.on_edu(
                "m.direct_to_device",
                "remote_server",
                {
                    "sender": "@user:remote_server",
                    "type": "m.room_key_request",
                    "messages": {user2: {"d2": {"idx": 3}}},
                    "message_id": "3",
                },
            )
        )

        # ... which should arrive
        channel = self.make_request(
            "GET", f"/sync?since={sync_token}", access_token=user2_tok
        )
        self.assertEqual(channel.code, 200, channel.result)
        msgs = channel.json_body["to_device"]["events"]
        self.assertEqual(len(msgs), 1)
        self.assertEqual(
            msgs[0],
            {
                "sender": "@user:remote_server",
                "type": "m.room_key_request",
                "content": {"idx": 3},
            },
        )
