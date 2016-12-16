# -*- coding: utf-8 -*-
# Copyright 2016 OpenMarket Ltd
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

import contextlib
import json

from mock import Mock, NonCallableMock
from twisted.internet import defer

import synapse.types
from synapse.replication.resource import ReplicationResource
from synapse.types import UserID
from tests import unittest
from tests.utils import setup_test_homeserver


class ReplicationResourceCase(unittest.TestCase):
    @defer.inlineCallbacks
    def setUp(self):
        self.hs = yield setup_test_homeserver(
            "red",
            http_client=None,
            replication_layer=Mock(),
            ratelimiter=NonCallableMock(spec_set=[
                "send_message",
            ]),
        )
        self.user_id = "@seeing:red"
        self.user = UserID.from_string(self.user_id)

        self.hs.get_ratelimiter().send_message.return_value = (True, 0)

        self.resource = ReplicationResource(self.hs)

    @defer.inlineCallbacks
    def test_streams(self):
        # Passing "-1" returns the current stream positions
        code, body = yield self.get(streams="-1")
        self.assertEquals(code, 200)
        self.assertEquals(body["streams"]["field_names"], ["name", "position"])
        position = body["streams"]["position"]
        # Passing the current position returns an empty response after the
        # timeout
        get = self.get(streams=str(position), timeout="0")
        self.hs.clock.advance_time_msec(1)
        code, body = yield get
        self.assertEquals(code, 200)
        self.assertEquals(body, {})

    @defer.inlineCallbacks
    def test_events(self):
        get = self.get(events="-1", timeout="0")
        yield self.hs.get_handlers().room_creation_handler.create_room(
            synapse.types.create_requester(self.user), {}
        )
        code, body = yield get
        self.assertEquals(code, 200)
        self.assertEquals(body["events"]["field_names"], [
            "position", "internal", "json", "state_group"
        ])

    @defer.inlineCallbacks
    def test_presence(self):
        get = self.get(presence="-1")
        yield self.hs.get_presence_handler().set_state(
            self.user, {"presence": "online"}
        )
        code, body = yield get
        self.assertEquals(code, 200)
        self.assertEquals(body["presence"]["field_names"], [
            "position", "user_id", "state", "last_active_ts",
            "last_federation_update_ts", "last_user_sync_ts",
            "status_msg", "currently_active",
        ])

    @defer.inlineCallbacks
    def test_typing(self):
        room_id = yield self.create_room()
        get = self.get(typing="-1")
        yield self.hs.get_typing_handler().started_typing(
            self.user, self.user, room_id, timeout=2
        )
        code, body = yield get
        self.assertEquals(code, 200)
        self.assertEquals(body["typing"]["field_names"], [
            "position", "room_id", "typing"
        ])

    @defer.inlineCallbacks
    def test_receipts(self):
        room_id = yield self.create_room()
        event_id = yield self.send_text_message(room_id, "Hello, World")
        get = self.get(receipts="-1")
        yield self.hs.get_receipts_handler().received_client_receipt(
            room_id, "m.read", self.user_id, event_id
        )
        code, body = yield get
        self.assertEquals(code, 200)
        self.assertEquals(body["receipts"]["field_names"], [
            "position", "room_id", "receipt_type", "user_id", "event_id", "data"
        ])

    def _test_timeout(stream):
        """Check that a request for the given stream timesout"""
        @defer.inlineCallbacks
        def test_timeout(self):
            get = self.get(**{stream: "-1", "timeout": "0"})
            self.hs.clock.advance_time_msec(1)
            code, body = yield get
            self.assertEquals(code, 200)
            self.assertEquals(body.get("rows", []), [])
        test_timeout.__name__ = "test_timeout_%s" % (stream)
        return test_timeout

    test_timeout_events = _test_timeout("events")
    test_timeout_presence = _test_timeout("presence")
    test_timeout_typing = _test_timeout("typing")
    test_timeout_receipts = _test_timeout("receipts")
    test_timeout_user_account_data = _test_timeout("user_account_data")
    test_timeout_room_account_data = _test_timeout("room_account_data")
    test_timeout_tag_account_data = _test_timeout("tag_account_data")
    test_timeout_backfill = _test_timeout("backfill")
    test_timeout_push_rules = _test_timeout("push_rules")
    test_timeout_pushers = _test_timeout("pushers")
    test_timeout_state = _test_timeout("state")

    @defer.inlineCallbacks
    def send_text_message(self, room_id, message):
        handler = self.hs.get_handlers().message_handler
        event = yield handler.create_and_send_nonmember_event(
            synapse.types.create_requester(self.user),
            {
                "type": "m.room.message",
                "content": {"body": "message", "msgtype": "m.text"},
                "room_id": room_id,
                "sender": self.user.to_string(),
            }
        )
        defer.returnValue(event.event_id)

    @defer.inlineCallbacks
    def create_room(self):
        result = yield self.hs.get_handlers().room_creation_handler.create_room(
            synapse.types.create_requester(self.user), {}
        )
        defer.returnValue(result["room_id"])

    @defer.inlineCallbacks
    def get(self, **params):
        request = NonCallableMock(spec_set=[
            "write", "finish", "setResponseCode", "setHeader", "args",
            "method", "processing"
        ])

        request.method = "GET"
        request.args = {k: [v] for k, v in params.items()}

        @contextlib.contextmanager
        def processing():
            yield
        request.processing = processing

        yield self.resource._async_render_GET(request)
        self.assertTrue(request.finish.called)

        if request.setResponseCode.called:
            response_code = request.setResponseCode.call_args[0][0]
        else:
            response_code = 200

        response_json = "".join(
            call[0][0] for call in request.write.call_args_list
        )
        response_body = json.loads(response_json)

        if response_code == 200:
            self.check_response(response_body)

        defer.returnValue((response_code, response_body))

    def check_response(self, response_body):
        for name, stream in response_body.items():
            self.assertIn("field_names", stream)
            field_names = stream["field_names"]
            self.assertIn("rows", stream)
            for row in stream["rows"]:
                self.assertEquals(
                    len(row), len(field_names),
                    "%s: len(row = %r) == len(field_names = %r)" % (
                        name, row, field_names
                    )
                )
