# -*- coding: utf-8 -*-
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


import json

from mock import ANY, Mock, call

from twisted.internet import defer

from synapse.api.errors import AuthError
from synapse.types import UserID

from tests import unittest

from ..utils import (
    DeferredMockCallable,
    MockClock,
    MockHttpResource,
    setup_test_homeserver,
)


def _expect_edu_transaction(edu_type, content, origin="test"):
    return {
        "origin": origin,
        "origin_server_ts": 1000000,
        "pdus": [],
        "edus": [{"edu_type": edu_type, "content": content}],
    }


def _make_edu_transaction_json(edu_type, content):
    return json.dumps(_expect_edu_transaction(edu_type, content)).encode('utf8')


class TypingNotificationsTestCase(unittest.TestCase):
    """Tests typing notifications to rooms."""

    @defer.inlineCallbacks
    def setUp(self):
        self.clock = MockClock()

        self.mock_http_client = Mock(spec=[])
        self.mock_http_client.put_json = DeferredMockCallable()

        self.mock_federation_resource = MockHttpResource()

        mock_notifier = Mock()
        self.on_new_event = mock_notifier.on_new_event

        self.auth = Mock(spec=[])
        self.state_handler = Mock()

        hs = yield setup_test_homeserver(
            self.addCleanup,
            "test",
            auth=self.auth,
            clock=self.clock,
            datastore=Mock(
                spec=[
                    # Bits that Federation needs
                    "prep_send_transaction",
                    "delivered_txn",
                    "get_received_txn_response",
                    "set_received_txn_response",
                    "get_destination_retry_timings",
                    "get_devices_by_remote",
                    # Bits that user_directory needs
                    "get_user_directory_stream_pos",
                    "get_current_state_deltas",
                ]
            ),
            state_handler=self.state_handler,
            handlers=Mock(),
            notifier=mock_notifier,
            resource_for_client=Mock(),
            resource_for_federation=self.mock_federation_resource,
            http_client=self.mock_http_client,
            keyring=Mock(),
        )

        self.handler = hs.get_typing_handler()

        self.event_source = hs.get_event_sources().sources["typing"]

        self.datastore = hs.get_datastore()
        retry_timings_res = {"destination": "", "retry_last_ts": 0, "retry_interval": 0}
        self.datastore.get_destination_retry_timings.return_value = defer.succeed(
            retry_timings_res
        )

        self.datastore.get_devices_by_remote.return_value = (0, [])

        def get_received_txn_response(*args):
            return defer.succeed(None)

        self.datastore.get_received_txn_response = get_received_txn_response

        self.room_id = "a-room"

        self.room_members = []

        def check_joined_room(room_id, user_id):
            if user_id not in [u.to_string() for u in self.room_members]:
                raise AuthError(401, "User is not in the room")

        def get_joined_hosts_for_room(room_id):
            return set(member.domain for member in self.room_members)

        self.datastore.get_joined_hosts_for_room = get_joined_hosts_for_room

        def get_current_user_in_room(room_id):
            return set(str(u) for u in self.room_members)

        self.state_handler.get_current_user_in_room = get_current_user_in_room

        self.datastore.get_user_directory_stream_pos.return_value = (
            # we deliberately return a non-None stream pos to avoid doing an initial_spam
            defer.succeed(1)
        )

        self.datastore.get_current_state_deltas.return_value = None

        self.auth.check_joined_room = check_joined_room

        self.datastore.get_to_device_stream_token = lambda: 0
        self.datastore.get_new_device_msgs_for_remote = lambda *args, **kargs: ([], 0)
        self.datastore.delete_device_msgs_for_remote = lambda *args, **kargs: None

        # Some local users to test with
        self.u_apple = UserID.from_string("@apple:test")
        self.u_banana = UserID.from_string("@banana:test")

        # Remote user
        self.u_onion = UserID.from_string("@onion:farm")

    @defer.inlineCallbacks
    def test_started_typing_local(self):
        self.room_members = [self.u_apple, self.u_banana]

        self.assertEquals(self.event_source.get_current_key(), 0)

        yield self.handler.started_typing(
            target_user=self.u_apple,
            auth_user=self.u_apple,
            room_id=self.room_id,
            timeout=20000,
        )

        self.on_new_event.assert_has_calls(
            [call('typing_key', 1, rooms=[self.room_id])]
        )

        self.assertEquals(self.event_source.get_current_key(), 1)
        events = yield self.event_source.get_new_events(
            room_ids=[self.room_id], from_key=0
        )
        self.assertEquals(
            events[0],
            [
                {
                    "type": "m.typing",
                    "room_id": self.room_id,
                    "content": {"user_ids": [self.u_apple.to_string()]},
                }
            ],
        )

    @defer.inlineCallbacks
    def test_started_typing_remote_send(self):
        self.room_members = [self.u_apple, self.u_onion]

        put_json = self.mock_http_client.put_json
        put_json.expect_call_and_return(
            call(
                "farm",
                path="/_matrix/federation/v1/send/1000000/",
                data=_expect_edu_transaction(
                    "m.typing",
                    content={
                        "room_id": self.room_id,
                        "user_id": self.u_apple.to_string(),
                        "typing": True,
                    },
                ),
                json_data_callback=ANY,
                long_retries=True,
                backoff_on_404=True,
            ),
            defer.succeed((200, "OK")),
        )

        yield self.handler.started_typing(
            target_user=self.u_apple,
            auth_user=self.u_apple,
            room_id=self.room_id,
            timeout=20000,
        )

        yield put_json.await_calls()

    @defer.inlineCallbacks
    def test_started_typing_remote_recv(self):
        self.room_members = [self.u_apple, self.u_onion]

        self.assertEquals(self.event_source.get_current_key(), 0)

        (code, response) = yield self.mock_federation_resource.trigger(
            "PUT",
            "/_matrix/federation/v1/send/1000000/",
            _make_edu_transaction_json(
                "m.typing",
                content={
                    "room_id": self.room_id,
                    "user_id": self.u_onion.to_string(),
                    "typing": True,
                },
            ),
            federation_auth_origin=b'farm',
        )

        self.on_new_event.assert_has_calls(
            [call('typing_key', 1, rooms=[self.room_id])]
        )

        self.assertEquals(self.event_source.get_current_key(), 1)
        events = yield self.event_source.get_new_events(
            room_ids=[self.room_id], from_key=0
        )
        self.assertEquals(
            events[0],
            [
                {
                    "type": "m.typing",
                    "room_id": self.room_id,
                    "content": {"user_ids": [self.u_onion.to_string()]},
                }
            ],
        )

    @defer.inlineCallbacks
    def test_stopped_typing(self):
        self.room_members = [self.u_apple, self.u_banana, self.u_onion]

        put_json = self.mock_http_client.put_json
        put_json.expect_call_and_return(
            call(
                "farm",
                path="/_matrix/federation/v1/send/1000000/",
                data=_expect_edu_transaction(
                    "m.typing",
                    content={
                        "room_id": self.room_id,
                        "user_id": self.u_apple.to_string(),
                        "typing": False,
                    },
                ),
                json_data_callback=ANY,
                long_retries=True,
                backoff_on_404=True,
            ),
            defer.succeed((200, "OK")),
        )

        # Gut-wrenching
        from synapse.handlers.typing import RoomMember

        member = RoomMember(self.room_id, self.u_apple.to_string())
        self.handler._member_typing_until[member] = 1002000
        self.handler._room_typing[self.room_id] = set([self.u_apple.to_string()])

        self.assertEquals(self.event_source.get_current_key(), 0)

        yield self.handler.stopped_typing(
            target_user=self.u_apple, auth_user=self.u_apple, room_id=self.room_id
        )

        self.on_new_event.assert_has_calls(
            [call('typing_key', 1, rooms=[self.room_id])]
        )

        yield put_json.await_calls()

        self.assertEquals(self.event_source.get_current_key(), 1)
        events = yield self.event_source.get_new_events(
            room_ids=[self.room_id], from_key=0
        )
        self.assertEquals(
            events[0],
            [
                {
                    "type": "m.typing",
                    "room_id": self.room_id,
                    "content": {"user_ids": []},
                }
            ],
        )

    @defer.inlineCallbacks
    def test_typing_timeout(self):
        self.room_members = [self.u_apple, self.u_banana]

        self.assertEquals(self.event_source.get_current_key(), 0)

        yield self.handler.started_typing(
            target_user=self.u_apple,
            auth_user=self.u_apple,
            room_id=self.room_id,
            timeout=10000,
        )

        self.on_new_event.assert_has_calls(
            [call('typing_key', 1, rooms=[self.room_id])]
        )
        self.on_new_event.reset_mock()

        self.assertEquals(self.event_source.get_current_key(), 1)
        events = yield self.event_source.get_new_events(
            room_ids=[self.room_id], from_key=0
        )
        self.assertEquals(
            events[0],
            [
                {
                    "type": "m.typing",
                    "room_id": self.room_id,
                    "content": {"user_ids": [self.u_apple.to_string()]},
                }
            ],
        )

        self.clock.advance_time(16)

        self.on_new_event.assert_has_calls(
            [call('typing_key', 2, rooms=[self.room_id])]
        )

        self.assertEquals(self.event_source.get_current_key(), 2)
        events = yield self.event_source.get_new_events(
            room_ids=[self.room_id], from_key=1
        )
        self.assertEquals(
            events[0],
            [
                {
                    "type": "m.typing",
                    "room_id": self.room_id,
                    "content": {"user_ids": []},
                }
            ],
        )

        # SYN-230 - see if we can still set after timeout

        yield self.handler.started_typing(
            target_user=self.u_apple,
            auth_user=self.u_apple,
            room_id=self.room_id,
            timeout=10000,
        )

        self.on_new_event.assert_has_calls(
            [call('typing_key', 3, rooms=[self.room_id])]
        )
        self.on_new_event.reset_mock()

        self.assertEquals(self.event_source.get_current_key(), 3)
        events = yield self.event_source.get_new_events(
            room_ids=[self.room_id], from_key=0
        )
        self.assertEquals(
            events[0],
            [
                {
                    "type": "m.typing",
                    "room_id": self.room_id,
                    "content": {"user_ids": [self.u_apple.to_string()]},
                }
            ],
        )
