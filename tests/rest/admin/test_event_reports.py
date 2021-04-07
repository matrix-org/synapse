# -*- coding: utf-8 -*-
# Copyright 2020 Dirk Klimpel
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
import random
import urllib
import uuid
from typing import Dict, List, Tuple

import synapse.rest.admin
from synapse.api.errors import Codes
from synapse.rest.client.v1 import login, room
from synapse.rest.client.v2_alpha import report_event, sync
from synapse.server_notices.server_notices_manager import ServerNoticesManager

from tests import unittest
from tests.unittest import override_config


class EventReportsTestCase(unittest.HomeserverTestCase):
    servlets = [
        synapse.rest.admin.register_servlets,
        login.register_servlets,
        room.register_servlets,
        report_event.register_servlets,
    ]

    def prepare(self, reactor, clock, hs):
        self.store = hs.get_datastore()

        self.admin_user = self.register_user("admin", "pass", admin=True)
        self.admin_user_tok = self.login("admin", "pass")

        self.other_user = self.register_user("user", "pass")
        self.other_user_tok = self.login("user", "pass")

        self.room_id1 = self.helper.create_room_as(
            self.other_user, tok=self.other_user_tok, is_public=True
        )
        self.helper.join(self.room_id1, user=self.admin_user, tok=self.admin_user_tok)

        self.room_id2 = self.helper.create_room_as(
            self.other_user, tok=self.other_user_tok, is_public=True
        )
        self.helper.join(self.room_id2, user=self.admin_user, tok=self.admin_user_tok)

        # Two rooms and two users. Every user sends and reports every room event
        for i in range(5):
            self._create_event_and_report(
                room_id=self.room_id1,
                user_tok=self.other_user_tok,
            )
        for i in range(5):
            self._create_event_and_report(
                room_id=self.room_id2,
                user_tok=self.other_user_tok,
            )
        for i in range(5):
            self._create_event_and_report(
                room_id=self.room_id1,
                user_tok=self.admin_user_tok,
            )
        for i in range(5):
            self._create_event_and_report(
                room_id=self.room_id2,
                user_tok=self.admin_user_tok,
            )

        self.url = "/_synapse/admin/v1/event_reports"

    def test_no_auth(self):
        """
        Try to get an event report without authentication.
        """
        channel = self.make_request("GET", self.url, b"{}")

        self.assertEqual(401, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual(Codes.MISSING_TOKEN, channel.json_body["errcode"])

    def test_requester_is_no_admin(self):
        """
        If the user is not a server admin, an error 403 is returned.
        """

        channel = self.make_request(
            "GET", self.url, access_token=self.other_user_tok,
        )

        self.assertEqual(403, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual(Codes.FORBIDDEN, channel.json_body["errcode"])

    def test_default_success(self):
        """
        Testing list of reported events
        """

        channel = self.make_request(
            "GET", self.url, access_token=self.admin_user_tok,
        )

        self.assertEqual(200, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual(channel.json_body["total"], 20)
        self.assertEqual(len(channel.json_body["event_reports"]), 20)
        self.assertNotIn("next_token", channel.json_body)
        self._check_fields(channel.json_body["event_reports"])

    def test_limit(self):
        """
        Testing list of reported events with limit
        """

        channel = self.make_request(
            "GET", self.url + "?limit=5", access_token=self.admin_user_tok,
        )

        self.assertEqual(200, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual(channel.json_body["total"], 20)
        self.assertEqual(len(channel.json_body["event_reports"]), 5)
        self.assertEqual(channel.json_body["next_token"], 5)
        self._check_fields(channel.json_body["event_reports"])

    def test_from(self):
        """
        Testing list of reported events with a defined starting point (from)
        """

        channel = self.make_request(
            "GET", self.url + "?from=5", access_token=self.admin_user_tok,
        )

        self.assertEqual(200, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual(channel.json_body["total"], 20)
        self.assertEqual(len(channel.json_body["event_reports"]), 15)
        self.assertNotIn("next_token", channel.json_body)
        self._check_fields(channel.json_body["event_reports"])

    def test_limit_and_from(self):
        """
        Testing list of reported events with a defined starting point and limit
        """

        channel = self.make_request(
            "GET", self.url + "?from=5&limit=10", access_token=self.admin_user_tok,
        )

        self.assertEqual(200, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual(channel.json_body["total"], 20)
        self.assertEqual(channel.json_body["next_token"], 15)
        self.assertEqual(len(channel.json_body["event_reports"]), 10)
        self._check_fields(channel.json_body["event_reports"])

    def test_filter_room(self):
        """
        Testing list of reported events with a filter of room
        """

        channel = self.make_request(
            "GET",
            self.url + "?room_id=%s" % self.room_id1,
            access_token=self.admin_user_tok,
        )

        self.assertEqual(200, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual(channel.json_body["total"], 10)
        self.assertEqual(len(channel.json_body["event_reports"]), 10)
        self.assertNotIn("next_token", channel.json_body)
        self._check_fields(channel.json_body["event_reports"])

        for report in channel.json_body["event_reports"]:
            self.assertEqual(report["room_id"], self.room_id1)

    def test_filter_user(self):
        """
        Testing list of reported events with a filter of user
        """

        channel = self.make_request(
            "GET",
            self.url + "?user_id=%s" % self.other_user,
            access_token=self.admin_user_tok,
        )

        self.assertEqual(200, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual(channel.json_body["total"], 10)
        self.assertEqual(len(channel.json_body["event_reports"]), 10)
        self.assertNotIn("next_token", channel.json_body)
        self._check_fields(channel.json_body["event_reports"])

        for report in channel.json_body["event_reports"]:
            self.assertEqual(report["user_id"], self.other_user)

    def test_filter_user_and_room(self):
        """
        Testing list of reported events with a filter of user and room
        """

        channel = self.make_request(
            "GET",
            self.url + "?user_id=%s&room_id=%s" % (self.other_user, self.room_id1),
            access_token=self.admin_user_tok,
        )

        self.assertEqual(200, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual(channel.json_body["total"], 5)
        self.assertEqual(len(channel.json_body["event_reports"]), 5)
        self.assertNotIn("next_token", channel.json_body)
        self._check_fields(channel.json_body["event_reports"])

        for report in channel.json_body["event_reports"]:
            self.assertEqual(report["user_id"], self.other_user)
            self.assertEqual(report["room_id"], self.room_id1)

    def test_valid_search_order(self):
        """
        Testing search order. Order by timestamps.
        """

        # fetch the most recent first, largest timestamp
        channel = self.make_request(
            "GET", self.url + "?dir=b", access_token=self.admin_user_tok,
        )

        self.assertEqual(200, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual(channel.json_body["total"], 20)
        self.assertEqual(len(channel.json_body["event_reports"]), 20)
        report = 1
        while report < len(channel.json_body["event_reports"]):
            self.assertGreaterEqual(
                channel.json_body["event_reports"][report - 1]["received_ts"],
                channel.json_body["event_reports"][report]["received_ts"],
            )
            report += 1

        # fetch the oldest first, smallest timestamp
        channel = self.make_request(
            "GET", self.url + "?dir=f", access_token=self.admin_user_tok,
        )

        self.assertEqual(200, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual(channel.json_body["total"], 20)
        self.assertEqual(len(channel.json_body["event_reports"]), 20)
        report = 1
        while report < len(channel.json_body["event_reports"]):
            self.assertLessEqual(
                channel.json_body["event_reports"][report - 1]["received_ts"],
                channel.json_body["event_reports"][report]["received_ts"],
            )
            report += 1

    def test_invalid_search_order(self):
        """
        Testing that a invalid search order returns a 400
        """

        channel = self.make_request(
            "GET", self.url + "?dir=bar", access_token=self.admin_user_tok,
        )

        self.assertEqual(400, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual(Codes.INVALID_PARAM, channel.json_body["errcode"])
        self.assertEqual("Unknown direction: bar", channel.json_body["error"])

    def test_limit_is_negative(self):
        """
        Testing that a negative limit parameter returns a 400
        """

        channel = self.make_request(
            "GET", self.url + "?limit=-5", access_token=self.admin_user_tok,
        )

        self.assertEqual(400, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual(Codes.INVALID_PARAM, channel.json_body["errcode"])

    def test_from_is_negative(self):
        """
        Testing that a negative from parameter returns a 400
        """

        channel = self.make_request(
            "GET", self.url + "?from=-5", access_token=self.admin_user_tok,
        )

        self.assertEqual(400, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual(Codes.INVALID_PARAM, channel.json_body["errcode"])

    def test_next_token(self):
        """
        Testing that `next_token` appears at the right place
        """

        #  `next_token` does not appear
        # Number of results is the number of entries
        channel = self.make_request(
            "GET", self.url + "?limit=20", access_token=self.admin_user_tok,
        )

        self.assertEqual(200, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual(channel.json_body["total"], 20)
        self.assertEqual(len(channel.json_body["event_reports"]), 20)
        self.assertNotIn("next_token", channel.json_body)

        #  `next_token` does not appear
        # Number of max results is larger than the number of entries
        channel = self.make_request(
            "GET", self.url + "?limit=21", access_token=self.admin_user_tok,
        )

        self.assertEqual(200, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual(channel.json_body["total"], 20)
        self.assertEqual(len(channel.json_body["event_reports"]), 20)
        self.assertNotIn("next_token", channel.json_body)

        #  `next_token` does appear
        # Number of max results is smaller than the number of entries
        channel = self.make_request(
            "GET", self.url + "?limit=19", access_token=self.admin_user_tok,
        )

        self.assertEqual(200, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual(channel.json_body["total"], 20)
        self.assertEqual(len(channel.json_body["event_reports"]), 19)
        self.assertEqual(channel.json_body["next_token"], 19)

        # Check
        # Set `from` to value of `next_token` for request remaining entries
        #  `next_token` does not appear
        channel = self.make_request(
            "GET", self.url + "?from=19", access_token=self.admin_user_tok,
        )

        self.assertEqual(200, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual(channel.json_body["total"], 20)
        self.assertEqual(len(channel.json_body["event_reports"]), 1)
        self.assertNotIn("next_token", channel.json_body)

    def _create_event_and_report(self, room_id, user_tok):
        """Create and report events
        """
        resp = self.helper.send(room_id, tok=user_tok)
        event_id = resp["event_id"]

        channel = self.make_request(
            "POST",
            "rooms/%s/report/%s" % (urllib.parse.quote(room_id), urllib.parse.quote(event_id)),
            {"score": -100, "reason": "this makes me sad"},
            access_token=user_tok,
        )
        self.assertEqual(200, int(channel.result["code"]), msg=channel.result["body"])

    def _check_fields(self, content):
        """Checks that all attributes are present in an event report
        """
        for c in content:
            self.assertIn("id", c)
            self.assertIn("received_ts", c)
            self.assertIn("room_id", c)
            self.assertIn("event_id", c)
            self.assertIn("user_id", c)
            self.assertIn("sender", c)
            self.assertIn("canonical_alias", c)
            self.assertIn("name", c)
            self.assertIn("score", c)
            self.assertIn("reason", c)


class EventReportDetailTestCase(unittest.HomeserverTestCase):
    servlets = [
        synapse.rest.admin.register_servlets,
        login.register_servlets,
        room.register_servlets,
        report_event.register_servlets,
    ]

    def prepare(self, reactor, clock, hs):
        self.store = hs.get_datastore()

        self.admin_user = self.register_user("admin", "pass", admin=True)
        self.admin_user_tok = self.login("admin", "pass")

        self.other_user = self.register_user("user", "pass")
        self.other_user_tok = self.login("user", "pass")

        self.room_id1 = self.helper.create_room_as(
            self.other_user, tok=self.other_user_tok, is_public=True
        )
        self.helper.join(self.room_id1, user=self.admin_user, tok=self.admin_user_tok)

        self._create_event_and_report(
            room_id=self.room_id1,
            user_tok=self.other_user_tok,
        )

        # first created event report gets `id`=2
        self.url = "/_synapse/admin/v1/event_reports/2"

    def test_no_auth(self):
        """
        Try to get event report without authentication.
        """
        channel = self.make_request("GET", self.url, b"{}")

        self.assertEqual(401, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual(Codes.MISSING_TOKEN, channel.json_body["errcode"])

    def test_requester_is_no_admin(self):
        """
        If the user is not a server admin, an error 403 is returned.
        """

        channel = self.make_request(
            "GET", self.url, access_token=self.other_user_tok,
        )

        self.assertEqual(403, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual(Codes.FORBIDDEN, channel.json_body["errcode"])

    def test_default_success(self):
        """
        Testing get a reported event
        """

        channel = self.make_request(
            "GET", self.url, access_token=self.admin_user_tok,
        )

        self.assertEqual(200, int(channel.result["code"]), msg=channel.result["body"])
        self._check_fields(channel.json_body)

    def test_invalid_report_id(self):
        """
        Testing that an invalid `report_id` returns a 400.
        """

        # `report_id` is negative
        channel = self.make_request(
            "GET",
            "/_synapse/admin/v1/event_reports/-123",
            access_token=self.admin_user_tok,
        )

        self.assertEqual(400, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual(Codes.INVALID_PARAM, channel.json_body["errcode"])
        self.assertEqual(
            "The report_id parameter must be a string representing a positive integer.",
            channel.json_body["error"],
        )

        # `report_id` is a non-numerical string
        channel = self.make_request(
            "GET",
            "/_synapse/admin/v1/event_reports/abcdef",
            access_token=self.admin_user_tok,
        )

        self.assertEqual(400, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual(Codes.INVALID_PARAM, channel.json_body["errcode"])
        self.assertEqual(
            "The report_id parameter must be a string representing a positive integer.",
            channel.json_body["error"],
        )

        # `report_id` is undefined
        channel = self.make_request(
            "GET",
            "/_synapse/admin/v1/event_reports/",
            access_token=self.admin_user_tok,
        )

        self.assertEqual(400, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual(Codes.INVALID_PARAM, channel.json_body["errcode"])
        self.assertEqual(
            "The report_id parameter must be a string representing a positive integer.",
            channel.json_body["error"],
        )

    def test_report_id_not_found(self):
        """
        Testing that a not existing `report_id` returns a 404.
        """

        channel = self.make_request(
            "GET",
            "/_synapse/admin/v1/event_reports/123",
            access_token=self.admin_user_tok,
        )

        self.assertEqual(404, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual(Codes.NOT_FOUND, channel.json_body["errcode"])
        self.assertEqual("Event report not found", channel.json_body["error"])

    def _create_event_and_report(self, room_id, user_tok):
        """Create and report events
        """
        resp = self.helper.send(room_id, tok=user_tok)
        event_id = resp["event_id"]

        channel = self.make_request(
            "POST",
            "rooms/%s/report/%s" % (urllib.parse.quote(room_id), urllib.parse.quote(event_id)),
            {"score": -100, "reason": "this makes me sad"},
            access_token=user_tok,
        )
        self.assertEqual(200, int(channel.result["code"]), msg=channel.result["body"])

    def _check_fields(self, content):
        """Checks that all attributes are present in a event report
        """
        self.assertIn("id", content)
        self.assertIn("received_ts", content)
        self.assertIn("room_id", content)
        self.assertIn("event_id", content)
        self.assertIn("user_id", content)
        self.assertIn("sender", content)
        self.assertIn("canonical_alias", content)
        self.assertIn("name", content)
        self.assertIn("event_json", content)
        self.assertIn("score", content)
        self.assertIn("reason", content)
        self.assertIn("auth_events", content["event_json"])
        self.assertIn("type", content["event_json"])
        self.assertIn("room_id", content["event_json"])
        self.assertIn("sender", content["event_json"])
        self.assertIn("content", content["event_json"])


class ReportToModeratorTestCase(unittest.HomeserverTestCase):
    """
    Test for MSC 2938: Reporting content to moderator instead of system
    administrator.
    """

    servlets = [
        sync.register_servlets,
        synapse.rest.admin.register_servlets,
        login.register_servlets,
        room.register_servlets,
        report_event.register_servlets,
    ]

    class TestUser:
        """
        Trivial container for users along with their role.
        """

        role: str
        mxid: str
        tok: str

        def __init__(self, mxid, tok, role):
            self.role = role
            self.mxid = mxid
            self.tok = tok

    class TestRoom:
        """
        Trivial container for rooms along with their config.
        """

        role: str
        is_public: bool
        is_encrypted: bool
        events: List

        def __init__(self, mxid, is_public, is_encrypted):
            self.mxid = mxid
            self.is_public = is_public
            self.events = []

    users: Dict[str, TestUser]
    rooms: List[TestRoom]
    url: str
    server_notices: ServerNoticesManager

    def prepare(self, reactor, clock, hs):
        # Prepare a bunch of users.
        self.users = {}
        for role in ["admin", "creator", "moderator", "author", "reporter", "exterior"]:
            self.users[role] = self.TestUser(
                role=role,
                mxid=self.register_user(
                    "user_%s" % role, "pass", admin=(role == "admin")
                ),
                tok=self.login("user_%s" % role, "pass"),
            )

        # Prepare a handful of rooms with distinct configurations.
        self.rooms = []
        user_creator = self.users["creator"]
        user_moderator = self.users["moderator"]
        for is_public in [False, True]:
            for is_encrypted in [False, True]:
                # Create the room.
                room_id = self.helper.create_room_as(
                    user_creator.mxid, tok=user_creator.tok, is_public=is_public
                )
                room = self.TestRoom(
                    is_public=is_public, is_encrypted=is_encrypted, mxid=room_id
                )
                self.rooms.append(room)

                # Join the room.
                for user in self.users.values():
                    if user.role != "exterior" and user.role != "creator":
                        self.helper.invite(
                            room_id,
                            src=user_creator.mxid,
                            targ=user.mxid,
                            tok=user_creator.tok,
                        )
                        self.helper.join(room_id, user=user.mxid, tok=user.tok)

                # Encrypt the room if necessary
                if is_encrypted:
                    self.helper.send_state(
                        room_id,
                        "m.room.encryption",
                        {"algorithm": "m.megolm.v1.aes-sha2"},
                        tok=user_creator.tok,
                        expect_code=200,
                    )

                # Mod the room.
                room_power_levels = self.helper.get_state(
                    room_id, "m.room.power_levels", tok=user_creator.tok,
                )
                room_power_levels["users"].update(
                    {user_moderator.mxid: 50, user_creator.mxid: 0}
                )
                self.helper.send_state(
                    room_id,
                    "m.room.power_levels",
                    room_power_levels,
                    tok=user_creator.tok,
                )

                # Populate the room with messages
                for i in range(0, 2):
                    for user in self.users.values():
                        if user.role != "exterior":
                            body = uuid.uuid4().hex
                            resp = self.helper.send(room_id, body=body, tok=user.tok)
                            room.events.append((resp["event_id"], body, room_id))

        self.url = "/_synapse/admin/v1/event_reports"
        self.server_notices = self.hs.get_server_notices_manager()

    def _get_notice_messages(self, user: TestUser):
        # Initial sync, to get any invite
        channel = self.make_request(
            "GET", "/_matrix/client/r0/sync", access_token=user.tok
        )
        self.assertEqual(int(channel.result["code"]), 200, channel.json_body)

        # Get the Room ID to join
        invites = channel.json_body["rooms"]["invite"]
        if len(invites) == 0:
            return None
        # The moderator MUST been invited.
        room_id = list(invites.keys())[0]

        # Join the room
        channel = self.make_request(
            "POST",
            "/_matrix/client/r0/rooms/" + room_id + "/join",
            access_token=user.tok,
        )
        self.assertEqual(int(channel.result["code"]), 200)

        # Sync again, to get the latest message in the room
        channel = self.make_request(
            "GET", "/_matrix/client/r0/sync", access_token=user.tok
        )
        self.assertEqual(int(channel.result["code"]), 200)

        # Get the messages
        room = channel.json_body["rooms"]["join"][room_id]
        messages = [
            x for x in room["timeline"]["events"] if x["type"] == "m.room.message"
        ]
        prev_batch = room["timeline"]["prev_batch"]
        while prev_batch is not None:
            channel = self.make_request(
                "GET",
                "/_matrix/client/r0/rooms/%(room_id)s/messages?from=%(from)s&dir=%(dir)s&limit=%(limit)s"
                % {"room_id": room_id, "from": prev_batch, "dir": "b", "limit": 100},
                access_token=user.tok,
            )
            prev_batch = channel.json_body.get("end", None)
            chunk = channel.json_body.get("chunk", [])
            if len(chunk) == 0:
                # No more messages to read
                break
            for event in chunk:
                if event["type"] == "m.room.message":
                    messages.append(event)

        return messages

    @override_config(
        {
            "server_notices": {"system_mxid_localpart": "server-notices"},
            "experimental_features": {"msc2983_enabled": True},
        }
    )
    def test_good_report(self):
        """
        A user who is member of the room reports an event in that room.

        The report should be accepted and received by the moderator as
        a server notice.
        """
        sent_reports_by_id: Dict[
            str, Dict[str, Tuple[ReportToModeratorTestCase.TestRoom, int, str]]
        ] = {}
        for current_room in self.rooms:
            for user in self.users.values():
                [partial_event_id, _, room_id] = current_room.events[
                    len(current_room.events) // 2
                ]
                event_id = "%s:%s" % (partial_event_id, self.hs.hostname)

                # Post report
                reason = uuid.uuid4().hex
                score = random.randrange(-100, 0)
                channel = self.make_request(
                    "POST",
                    "/_matrix/client/r0/rooms/%s/report/%s" % (room_id, event_id),
                    {
                        "score": score,
                        "reason": reason,
                        "org.matrix.msc2938.target": "room-moderators",
                    },
                    access_token=user.tok,
                )

                if user.role == "exterior":
                    # The exterior cannot post the report because they can't witness the event.
                    self.assertEqual(
                        400, int(channel.result["code"]), msg=channel.result["body"]
                    )
                else:
                    # Everybody else can post the report
                    reports_for_id = sent_reports_by_id.get(event_id, None)
                    if reports_for_id is None:
                        reports_for_id = {}
                        sent_reports_by_id[event_id] = reports_for_id
                    reports_for_id[user.mxid] = (current_room, score, reason)
                    self.assertEqual(
                        200, int(channel.result["code"]), msg=channel.result["body"]
                    )

        for user in self.users.values():
            messages = self._get_notice_messages(user)
            if user.role != "moderator":
                # Only the moderator should receive messages.
                self.assertEquals(
                    messages, None, "We shouldn't receive messages %s" % messages
                )
            else:
                # The moderator should receive all the messages.
                for message in messages:
                    reported_event_id = message["content"]["eventId"]
                    reporter_user_id = message["content"]["userId"]

                    sent_reports_for_event_id = sent_reports_by_id[reported_event_id]
                    sent_report = sent_reports_for_event_id[reporter_user_id]

                    self.assertEqual(sent_report[0].mxid, message["content"]["roomId"])
                    self.assertEqual(sent_report[1], int(message["content"]["score"]))
                    self.assertEqual(sent_report[2], message["content"]["reason"])

                    # Progressively clean up sent_reports_by_id, it should
                    # be empty by the time we're done.
                    del sent_reports_for_event_id[reporter_user_id]
                    if len(sent_reports_for_event_id) == 0:
                        del sent_reports_by_id[reported_event_id]

        self.assertEquals(
            len(sent_reports_by_id),
            0,
            "We should have received all the messages %s" % sent_reports_by_id,
        )

    @override_config(
        {
            "server_notices": {"system_mxid_localpart": "reporter"},
            "experimental_features": {"msc2983_enabled": True},
        }
    )
    def test_bad_report(self):
        """
        Sending a report with an event id that is ill-formed will trigger an error.
        """
        for user in self.users.values():
            channel = self.make_request(
                "POST",
                "/_matrix/client/r0/rooms/%s/report/%s"
                % (
                    self.rooms[0].mxid,
                    "if-you-look-closely-you-will-realize-that-this-event-id-is-somewhat-fishy",
                ),
                {
                    "score": -100,
                    "reason": "some reason",
                    "org.matrix.msc2938.target": "room-moderators",
                },
                access_token=user.tok,
            )
            self.assertEqual(
                400, int(channel.result["code"]), msg=channel.result["body"]
            )

    @override_config(
        {"server_notices": None, "experimental_features": {"msc2983_enabled": True}}
    )
    def test_no_notices(self):
        """
        Sending a report with user notices doesn't cause an error.
        """
        for current_room in self.rooms:
            for user in self.users.values():
                [partial_event_id, _, room_id] = current_room.events[
                    len(current_room.events) // 2
                ]
                event_id = "%s:%s" % (partial_event_id, self.hs.hostname)

                # Post report
                reason = uuid.uuid4().hex
                score = random.randrange(-100, 0)
                channel = self.make_request(
                    "POST",
                    "/_matrix/client/r0/rooms/%s/report/%s" % (room_id, event_id),
                    {
                        "score": score,
                        "reason": reason,
                        "org.matrix.msc2938.target": "room-moderators",
                    },
                    access_token=user.tok,
                )

                if user.role == "exterior":
                    # The exterior cannot post the report because they can't witness the event.
                    self.assertEqual(
                        400, int(channel.result["code"]), msg=channel.result["body"]
                    )
                else:
                    # Everybody else can post the report (although it will be ignored
                    # in this case).
                    self.assertEqual(
                        200, int(channel.result["code"]), msg=channel.result["body"]
                    )
