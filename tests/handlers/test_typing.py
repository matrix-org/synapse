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

from ..utils import MockHttpResource, MockClock, DeferredMockCallable, MockKey

from synapse.server import HomeServer
from synapse.handlers.typing import TypingNotificationHandler


def _expect_edu(destination, edu_type, content, origin="test"):
    return {
        "origin": origin,
        "ts": 1000000,
        "pdus": [],
        "edus": [
            {
                # TODO: SYN-103: Remove "origin" and "destination" keys.
                "origin": origin,
                "destination": destination,
                "edu_type": edu_type,
                "content": content,
            }
        ],
    }


def _make_edu_json(origin, edu_type, content):
    return json.dumps(_expect_edu("test", edu_type, content, origin=origin))


class JustTypingNotificationHandlers(object):
    def __init__(self, hs):
        self.typing_notification_handler = TypingNotificationHandler(hs)


class TypingNotificationsTestCase(unittest.TestCase):
    """Tests typing notifications to rooms."""
    def setUp(self):
        self.clock = MockClock()

        self.mock_http_client = Mock(spec=[])
        self.mock_http_client.put_json = DeferredMockCallable()

        self.mock_federation_resource = MockHttpResource()

        self.mock_config = Mock()
        self.mock_config.signing_key = [MockKey()]

        hs = HomeServer("test",
                clock=self.clock,
                db_pool=None,
                datastore=Mock(spec=[
                    # Bits that Federation needs
                    "prep_send_transaction",
                    "delivered_txn",
                    "get_received_txn_response",
                    "set_received_txn_response",
                ]),
                handlers=None,
                resource_for_client=Mock(),
                resource_for_federation=self.mock_federation_resource,
                http_client=self.mock_http_client,
                config=self.mock_config,
                keyring=Mock(),
            )
        hs.handlers = JustTypingNotificationHandlers(hs)

        self.mock_update_client = Mock()
        self.mock_update_client.return_value = defer.succeed(None)

        self.handler = hs.get_handlers().typing_notification_handler
        self.handler.push_update_to_clients = self.mock_update_client

        self.datastore = hs.get_datastore()

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

                if member.is_mine:
                    if localusers is not None:
                        localusers.add(member)
                else:
                    if remotedomains is not None:
                        remotedomains.add(member.domain)
        self.room_member_handler.fetch_room_distributions_into = (
                fetch_room_distributions_into)

        # Some local users to test with
        self.u_apple = hs.parse_userid("@apple:test")
        self.u_banana = hs.parse_userid("@banana:test")

        # Remote user
        self.u_onion = hs.parse_userid("@onion:farm")

    @defer.inlineCallbacks
    def test_started_typing_local(self):
        self.room_members = [self.u_apple, self.u_banana]

        yield self.handler.started_typing(
            target_user=self.u_apple,
            auth_user=self.u_apple,
            room_id=self.room_id,
            timeout=20000,
        )

        self.mock_update_client.assert_has_calls([
            call(observer_user=self.u_banana,
                observed_user=self.u_apple,
                room_id=self.room_id,
                typing=True),
        ])

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

        self.mock_update_client.assert_has_calls([
            call(observer_user=self.u_apple,
                observed_user=self.u_onion,
                room_id=self.room_id,
                typing=True),
        ])

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
        self.handler._member_typing_until[
            RoomMember(self.room_id, self.u_apple)
        ] = 1002000

        yield self.handler.stopped_typing(
            target_user=self.u_apple,
            auth_user=self.u_apple,
            room_id=self.room_id,
        )

        self.mock_update_client.assert_has_calls([
            call(observer_user=self.u_banana,
                observed_user=self.u_apple,
                room_id=self.room_id,
                typing=False),
        ])

        yield put_json.await_calls()
