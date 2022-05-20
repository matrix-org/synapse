# Copyright 2019 The Matrix.org Foundation C.I.C.
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
from typing import List

from twisted.test.proto_helpers import MemoryReactor

from synapse.rest import admin
from synapse.rest.client import login, room, sync
from synapse.server import HomeServer
from synapse.types import JsonDict
from synapse.util import Clock

from tests.unittest import HomeserverTestCase


class RedactionsTestCase(HomeserverTestCase):
    """Tests that various redaction events are handled correctly"""

    servlets = [
        admin.register_servlets,
        room.register_servlets,
        login.register_servlets,
        sync.register_servlets,
    ]

    def make_homeserver(self, reactor: MemoryReactor, clock: Clock) -> HomeServer:
        config = self.default_config()

        config["rc_message"] = {"per_second": 0.2, "burst_count": 10}
        config["rc_admin_redaction"] = {"per_second": 1, "burst_count": 100}

        return self.setup_test_homeserver(config=config)

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        # register a couple of users
        self.mod_user_id = self.register_user("user1", "pass")
        self.mod_access_token = self.login("user1", "pass")
        self.other_user_id = self.register_user("otheruser", "pass")
        self.other_access_token = self.login("otheruser", "pass")

        # Create a room
        self.room_id = self.helper.create_room_as(
            self.mod_user_id, tok=self.mod_access_token
        )

        # Invite the other user
        self.helper.invite(
            room=self.room_id,
            src=self.mod_user_id,
            tok=self.mod_access_token,
            targ=self.other_user_id,
        )
        # The other user joins
        self.helper.join(
            room=self.room_id, user=self.other_user_id, tok=self.other_access_token
        )

    def _redact_event(
        self, access_token: str, room_id: str, event_id: str, expect_code: int = 200
    ) -> JsonDict:
        """Helper function to send a redaction event.

        Returns the json body.
        """
        path = "/_matrix/client/r0/rooms/%s/redact/%s" % (room_id, event_id)

        channel = self.make_request("POST", path, content={}, access_token=access_token)
        self.assertEqual(int(channel.result["code"]), expect_code)
        return channel.json_body

    def _sync_room_timeline(self, access_token: str, room_id: str) -> List[JsonDict]:
        channel = self.make_request("GET", "sync", access_token=self.mod_access_token)
        self.assertEqual(channel.result["code"], b"200")
        room_sync = channel.json_body["rooms"]["join"][room_id]
        return room_sync["timeline"]["events"]

    def test_redact_event_as_moderator(self) -> None:
        # as a regular user, send a message to redact
        b = self.helper.send(room_id=self.room_id, tok=self.other_access_token)
        msg_id = b["event_id"]

        # as the moderator, send a redaction
        b = self._redact_event(self.mod_access_token, self.room_id, msg_id)
        redaction_id = b["event_id"]

        # now sync
        timeline = self._sync_room_timeline(self.mod_access_token, self.room_id)

        # the last event should be the redaction
        self.assertEqual(timeline[-1]["event_id"], redaction_id)
        self.assertEqual(timeline[-1]["redacts"], msg_id)

        # and the penultimate should be the redacted original
        self.assertEqual(timeline[-2]["event_id"], msg_id)
        self.assertEqual(timeline[-2]["unsigned"]["redacted_by"], redaction_id)
        self.assertEqual(timeline[-2]["content"], {})

    def test_redact_event_as_normal(self) -> None:
        # as a regular user, send a message to redact
        b = self.helper.send(room_id=self.room_id, tok=self.other_access_token)
        normal_msg_id = b["event_id"]

        # also send one as the admin
        b = self.helper.send(room_id=self.room_id, tok=self.mod_access_token)
        admin_msg_id = b["event_id"]

        # as a normal, try to redact the admin's event
        self._redact_event(
            self.other_access_token, self.room_id, admin_msg_id, expect_code=403
        )

        # now try to redact our own event
        b = self._redact_event(self.other_access_token, self.room_id, normal_msg_id)
        redaction_id = b["event_id"]

        # now sync
        timeline = self._sync_room_timeline(self.other_access_token, self.room_id)

        # the last event should be the redaction of the normal event
        self.assertEqual(timeline[-1]["event_id"], redaction_id)
        self.assertEqual(timeline[-1]["redacts"], normal_msg_id)

        # the penultimate should be the unredacted one from the admin
        self.assertEqual(timeline[-2]["event_id"], admin_msg_id)
        self.assertNotIn("redacted_by", timeline[-2]["unsigned"])
        self.assertTrue(timeline[-2]["content"]["body"], {})

        # and the antepenultimate should be the redacted normal
        self.assertEqual(timeline[-3]["event_id"], normal_msg_id)
        self.assertEqual(timeline[-3]["unsigned"]["redacted_by"], redaction_id)
        self.assertEqual(timeline[-3]["content"], {})

    def test_redact_nonexistent_event(self) -> None:
        # control case: an existing event
        b = self.helper.send(room_id=self.room_id, tok=self.other_access_token)
        msg_id = b["event_id"]
        b = self._redact_event(self.other_access_token, self.room_id, msg_id)
        redaction_id = b["event_id"]

        # room moderators can send redactions for non-existent events
        self._redact_event(self.mod_access_token, self.room_id, "$zzz")

        # ... but normals cannot
        self._redact_event(
            self.other_access_token, self.room_id, "$zzz", expect_code=404
        )

        # when we sync, we should see only the valid redaction
        timeline = self._sync_room_timeline(self.other_access_token, self.room_id)
        self.assertEqual(timeline[-1]["event_id"], redaction_id)
        self.assertEqual(timeline[-1]["redacts"], msg_id)

        # and the penultimate should be the redacted original
        self.assertEqual(timeline[-2]["event_id"], msg_id)
        self.assertEqual(timeline[-2]["unsigned"]["redacted_by"], redaction_id)
        self.assertEqual(timeline[-2]["content"], {})

    def test_redact_create_event(self) -> None:
        # control case: an existing event
        b = self.helper.send(room_id=self.room_id, tok=self.mod_access_token)
        msg_id = b["event_id"]
        self._redact_event(self.mod_access_token, self.room_id, msg_id)

        # sync the room, to get the id of the create event
        timeline = self._sync_room_timeline(self.other_access_token, self.room_id)
        create_event_id = timeline[0]["event_id"]

        # room moderators cannot send redactions for create events
        self._redact_event(
            self.mod_access_token, self.room_id, create_event_id, expect_code=403
        )

        # and nor can normals
        self._redact_event(
            self.other_access_token, self.room_id, create_event_id, expect_code=403
        )

    def test_redact_event_as_moderator_ratelimit(self) -> None:
        """Tests that the correct ratelimiting is applied to redactions"""

        message_ids = []
        # as a regular user, send messages to redact
        for _ in range(20):
            b = self.helper.send(room_id=self.room_id, tok=self.other_access_token)
            message_ids.append(b["event_id"])
            self.reactor.advance(10)  # To get around ratelimits

        # as the moderator, send a bunch of redactions
        for msg_id in message_ids:
            # These should all succeed, even though this would be denied by
            # the standard message ratelimiter
            self._redact_event(self.mod_access_token, self.room_id, msg_id)
