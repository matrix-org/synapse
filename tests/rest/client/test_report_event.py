# Copyright 2021 Callum Brown
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

from twisted.test.proto_helpers import MemoryReactor

import synapse.rest.admin
from synapse.rest.client import login, report_event, room
from synapse.server import HomeServer
from synapse.types import JsonDict
from synapse.util import Clock

from tests import unittest


class ReportEventTestCase(unittest.HomeserverTestCase):
    servlets = [
        synapse.rest.admin.register_servlets,
        login.register_servlets,
        room.register_servlets,
        report_event.register_servlets,
    ]

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self.admin_user = self.register_user("admin", "pass", admin=True)
        self.admin_user_tok = self.login("admin", "pass")
        self.other_user = self.register_user("user", "pass")
        self.other_user_tok = self.login("user", "pass")

        self.room_id = self.helper.create_room_as(
            self.other_user, tok=self.other_user_tok, is_public=True
        )
        self.helper.join(self.room_id, user=self.admin_user, tok=self.admin_user_tok)
        resp = self.helper.send(self.room_id, tok=self.admin_user_tok)
        self.event_id = resp["event_id"]
        self.report_path = f"rooms/{self.room_id}/report/{self.event_id}"

    def test_reason_str_and_score_int(self) -> None:
        data = {"reason": "this makes me sad", "score": -100}
        self._assert_status(200, data)

    def test_no_reason(self) -> None:
        data = {"score": 0}
        self._assert_status(200, data)

    def test_no_score(self) -> None:
        data = {"reason": "this makes me sad"}
        self._assert_status(200, data)

    def test_no_reason_and_no_score(self) -> None:
        data: JsonDict = {}
        self._assert_status(200, data)

    def test_reason_int_and_score_str(self) -> None:
        data = {"reason": 10, "score": "string"}
        self._assert_status(400, data)

    def test_reason_zero_and_score_blank(self) -> None:
        data = {"reason": 0, "score": ""}
        self._assert_status(400, data)

    def test_reason_and_score_null(self) -> None:
        data = {"reason": None, "score": None}
        self._assert_status(400, data)

    def test_cannot_report_nonexistent_event(self) -> None:
        """
        Tests that we don't accept event reports for events which do not exist.
        """
        channel = self.make_request(
            "POST",
            f"rooms/{self.room_id}/report/$nonsenseeventid:test",
            {"reason": "i am very sad"},
            access_token=self.other_user_tok,
        )
        self.assertEqual(404, channel.code, msg=channel.result["body"])
        self.assertEqual(
            "Unable to report event: it does not exist or you aren't able to see it.",
            channel.json_body["error"],
            msg=channel.result["body"],
        )

    def test_cannot_report_event_if_not_in_room(self) -> None:
        """
        Tests that we don't accept event reports for events that exist, but for which
        the reporter should not be able to view (because they are not in the room).
        """
        # Have the admin user create a room (the "other" user will not join this room).
        new_room_id = self.helper.create_room_as(tok=self.admin_user_tok)

        # Have the admin user send an event in this room.
        response = self.helper.send_event(
            new_room_id,
            "m.room.message",
            content={
                "msgtype": "m.text",
                "body": "This event has some bad words in it! Flip!",
            },
            tok=self.admin_user_tok,
        )
        event_id = response["event_id"]

        # Have the "other" user attempt to report it. Perhaps they found the event ID
        # in a screenshot or something...
        channel = self.make_request(
            "POST",
            f"rooms/{new_room_id}/report/{event_id}",
            {"reason": "I'm not in this room but I have opinions anyways!"},
            access_token=self.other_user_tok,
        )

        # The "other" user is not in the room, so their report should be rejected.
        self.assertEqual(404, channel.code, msg=channel.result["body"])
        self.assertEqual(
            "Unable to report event: it does not exist or you aren't able to see it.",
            channel.json_body["error"],
            msg=channel.result["body"],
        )

    def _assert_status(self, response_status: int, data: JsonDict) -> None:
        channel = self.make_request(
            "POST", self.report_path, data, access_token=self.other_user_tok
        )
        self.assertEqual(response_status, channel.code, msg=channel.result["body"])
