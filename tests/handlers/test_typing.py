# -*- coding: utf-8 -*-
# Copyright 2014 OpenMarket Ltd
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


from tests import unittest
from twisted.internet import defer

from mock import Mock, call, ANY
import json

from ..utils import (
    MockHttpResource, MockClock, DeferredMockCallable, setup_test_homeserver
)

from synapse.api.errors import AuthError
from synapse.handlers.typing import TypingNotificationHandler

from synapse.storage.transactions import DestinationsTable
from synapse.types import UserID


def _expect_edu(destination, edu_type, content, origin="test"):
    return {
        "origin": origin,
        "origin_server_ts": 1000000,
        "pdus": [],
        "edus": [
            {
                "edu_type": edu_type,
                "content": content,
            }
        ],
        "pdu_failures": [],
    }


def _make_edu_json(origin, edu_type, content):
    return json.dumps(_expect_edu("test", edu_type, content, origin=origin))


class JustTypingNotificationHandlers(object):
    def __init__(self, hs):
        self.typing_notification_handler = TypingNotificationHandler(hs)


class TypingNotificationsTestCase(unittest.TestCase):
    """Tests typing notifications to rooms."""
    @defer.inlineCallbacks
    def setUp(self):
        self.clock = MockClock()

        self.mock_http_client = Mock(spec=[])
        self.mock_http_client.put_json = DeferredMockCallable()

        self.mock_federation_resource = MockHttpResource()

        mock_notifier = Mock(spec=["on_new_user_event"])
        self.on_new_user_event = mock_notifier.on_new_user_event

        self.auth = Mock(spec=[])

        hs = yield setup_test_homeserver(
            auth=self.auth,
            clock=self.clock,
            datastore=Mock(spec=[
                # Bits that Federation needs
                "prep_send_transaction",
                "delivered_txn",
                "get_received_txn_response",
                "set_received_txn_response",
                "get_destination_retry_timings",
            ]),
            handlers=None,
            notifier=mock_notifier,
            resource_for_client=Mock(),
            resource_for_federation=self.mock_federation_resource,
            http_client=self.mock_http_client,
            keyring=Mock(),
        )
        hs.handlers = JustTypingNotificationHandlers(hs)

        self.handler = hs.get_handlers().typing_notification_handler

        self.event_source = hs.get_event_sources().sources["typing"]

        self.datastore = hs.get_datastore()
        self.datastore.get_destination_retry_timings.return_value = (
            defer.succeed(DestinationsTable.EntryType("", 0, 0))
        )

        def get_received_txn_response(*args):
            return defer.succeed(None)
        self.datastore.get_received_txn_response = get_received_txn_response

        self.room_id = "a-room"

        # Mock the RoomMemberHandler
        hs.handlers.room_member_handler = Mock(spec=[])
        self.room_member_handler = hs.handlers.room_member_handler

        self.room_members = []

        def get_rooms_for_user(user):
            if user in self.room_members:
                return defer.succeed([self.room_id])
            else:
                return defer.succeed([])
        self.room_member_handler.get_rooms_for_user = get_rooms_for_user

        def get_room_members(room_id):
            if room_id == self.room_id:
                return defer.succeed(self.room_members)
            else:
                return defer.succeed([])
        self.room_member_handler.get_room_members = get_room_members

        @defer.inlineCallbacks
        def fetch_room_distributions_into(room_id, localusers=None,
                remotedomains=None, ignore_user=None):

            members = yield get_room_members(room_id)
            for member in members:
                if ignore_user is not None and member == ignore_user:
                    continue

                if hs.is_mine(member):
                    if localusers is not None:
                        localusers.add(member)
                else:
                    if remotedomains is not None:
                        remotedomains.add(member.domain)
        self.room_member_handler.fetch_room_distributions_into = (
                fetch_room_distributions_into)

        def check_joined_room(room_id, user_id):
            if user_id not in [u.to_string() for u in self.room_members]:
                raise AuthError(401, "User is not in the room")

        self.auth.check_joined_room = check_joined_room

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

        self.on_new_user_event.assert_has_calls([
            call(rooms=[self.room_id]),
        ])

        self.assertEquals(self.event_source.get_current_key(), 1)
        self.assertEquals(
            self.event_source.get_new_events_for_user(self.u_apple, 0, None)[0],
            [
                {"type": "m.typing",
                 "room_id": self.room_id,
                 "content": {
                     "user_ids": [self.u_apple.to_string()],
                 }},
            ]
        )

    @defer.inlineCallbacks
    def test_started_typing_remote_send(self):
        self.room_members = [self.u_apple, self.u_onion]

        put_json = self.mock_http_client.put_json
        put_json.expect_call_and_return(
            call("farm",
                path="/_matrix/federation/v1/send/1000000/",
                data=_expect_edu("farm", "m.typing",
                    content={
                        "room_id": self.room_id,
                        "user_id": self.u_apple.to_string(),
                        "typing": True,
                    }
                ),
                json_data_callback=ANY,
            ),
            defer.succeed((200, "OK"))
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

        yield self.mock_federation_resource.trigger("PUT",
            "/_matrix/federation/v1/send/1000000/",
            _make_edu_json("farm", "m.typing",
                content={
                    "room_id": self.room_id,
                    "user_id": self.u_onion.to_string(),
                    "typing": True,
                }
            )
        )

        self.on_new_user_event.assert_has_calls([
            call(rooms=[self.room_id]),
        ])

        self.assertEquals(self.event_source.get_current_key(), 1)
        self.assertEquals(
            self.event_source.get_new_events_for_user(self.u_apple, 0, None)[0],
            [
                {"type": "m.typing",
                 "room_id": self.room_id,
                 "content": {
                     "user_ids": [self.u_onion.to_string()],
                }},
            ]
        )

    @defer.inlineCallbacks
    def test_stopped_typing(self):
        self.room_members = [self.u_apple, self.u_banana, self.u_onion]

        put_json = self.mock_http_client.put_json
        put_json.expect_call_and_return(
            call("farm",
                path="/_matrix/federation/v1/send/1000000/",
                data=_expect_edu("farm", "m.typing",
                    content={
                        "room_id": self.room_id,
                        "user_id": self.u_apple.to_string(),
                        "typing": False,
                    }
                ),
                json_data_callback=ANY,
            ),
            defer.succeed((200, "OK"))
        )

        # Gut-wrenching
        from synapse.handlers.typing import RoomMember
        member = RoomMember(self.room_id, self.u_apple)
        self.handler._member_typing_until[member] = 1002000
        self.handler._member_typing_timer[member] = (
            self.clock.call_later(1002, lambda: 0)
        )
        self.handler._room_typing[self.room_id] = set((self.u_apple,))

        self.assertEquals(self.event_source.get_current_key(), 0)

        yield self.handler.stopped_typing(
            target_user=self.u_apple,
            auth_user=self.u_apple,
            room_id=self.room_id,
        )

        self.on_new_user_event.assert_has_calls([
            call(rooms=[self.room_id]),
        ])

        yield put_json.await_calls()

        self.assertEquals(self.event_source.get_current_key(), 1)
        self.assertEquals(
            self.event_source.get_new_events_for_user(self.u_apple, 0, None)[0],
            [
                {"type": "m.typing",
                 "room_id": self.room_id,
                 "content": {
                     "user_ids": [],
                }},
            ]
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

        self.on_new_user_event.assert_has_calls([
            call(rooms=[self.room_id]),
        ])
        self.on_new_user_event.reset_mock()

        self.assertEquals(self.event_source.get_current_key(), 1)
        self.assertEquals(
            self.event_source.get_new_events_for_user(self.u_apple, 0, None)[0],
            [
                {"type": "m.typing",
                 "room_id": self.room_id,
                 "content": {
                     "user_ids": [self.u_apple.to_string()],
                }},
            ]
        )

        self.clock.advance_time(11)

        self.on_new_user_event.assert_has_calls([
            call(rooms=[self.room_id]),
        ])

        self.assertEquals(self.event_source.get_current_key(), 2)
        self.assertEquals(
            self.event_source.get_new_events_for_user(self.u_apple, 1, None)[0],
            [
                {"type": "m.typing",
                 "room_id": self.room_id,
                 "content": {
                     "user_ids": [],
                }},
            ]
        )

        # SYN-230 - see if we can still set after timeout

        yield self.handler.started_typing(
            target_user=self.u_apple,
            auth_user=self.u_apple,
            room_id=self.room_id,
            timeout=10000,
        )

        self.on_new_user_event.assert_has_calls([
            call(rooms=[self.room_id]),
        ])
        self.on_new_user_event.reset_mock()

        self.assertEquals(self.event_source.get_current_key(), 3)
        self.assertEquals(
            self.event_source.get_new_events_for_user(self.u_apple, 0, None)[0],
            [
                {"type": "m.typing",
                 "room_id": self.room_id,
                 "content": {
                     "user_ids": [self.u_apple.to_string()],
                }},
            ]
        )
