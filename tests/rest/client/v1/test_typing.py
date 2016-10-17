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

"""Tests REST events for /rooms paths."""

# twisted imports
from twisted.internet import defer

import synapse.rest.client.v1.room
from synapse.types import UserID

from ....utils import MockHttpResource, MockClock, setup_test_homeserver
from .utils import RestTestCase

from mock import Mock, NonCallableMock


PATH_PREFIX = "/_matrix/client/api/v1"


class RoomTypingTestCase(RestTestCase):
    """ Tests /rooms/$room_id/typing/$user_id REST API. """
    user_id = "@sid:red"

    user = UserID.from_string(user_id)

    @defer.inlineCallbacks
    def setUp(self):
        self.clock = MockClock()

        self.mock_resource = MockHttpResource(prefix=PATH_PREFIX)
        self.auth_user_id = self.user_id

        hs = yield setup_test_homeserver(
            "red",
            clock=self.clock,
            http_client=None,
            replication_layer=Mock(),
            ratelimiter=NonCallableMock(spec_set=[
                "send_message",
            ]),
        )
        self.hs = hs

        self.event_source = hs.get_event_sources().sources["typing"]

        self.ratelimiter = hs.get_ratelimiter()
        self.ratelimiter.send_message.return_value = (True, 0)

        hs.get_handlers().federation_handler = Mock()

        def get_user_by_access_token(token=None, allow_guest=False):
            return {
                "user": UserID.from_string(self.auth_user_id),
                "token_id": 1,
                "is_guest": False,
            }

        hs.get_v1auth().get_user_by_access_token = get_user_by_access_token

        def _insert_client_ip(*args, **kwargs):
            return defer.succeed(None)
        hs.get_datastore().insert_client_ip = _insert_client_ip

        def get_room_members(room_id):
            if room_id == self.room_id:
                return defer.succeed([self.user])
            else:
                return defer.succeed([])

        @defer.inlineCallbacks
        def fetch_room_distributions_into(
            room_id, localusers=None, remotedomains=None, ignore_user=None
        ):
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
        hs.get_handlers().room_member_handler.fetch_room_distributions_into = (
            fetch_room_distributions_into
        )

        synapse.rest.client.v1.room.register_servlets(hs, self.mock_resource)

        self.room_id = yield self.create_room_as(self.user_id)
        # Need another user to make notifications actually work
        yield self.join(self.room_id, user="@jim:red")

    @defer.inlineCallbacks
    def test_set_typing(self):
        (code, _) = yield self.mock_resource.trigger(
            "PUT", "/rooms/%s/typing/%s" % (self.room_id, self.user_id),
            '{"typing": true, "timeout": 30000}'
        )
        self.assertEquals(200, code)

        self.assertEquals(self.event_source.get_current_key(), 1)
        events = yield self.event_source.get_new_events(
            from_key=0,
            room_ids=[self.room_id],
        )
        self.assertEquals(events[0], [{
            "type": "m.typing",
            "room_id": self.room_id,
            "content": {
                "user_ids": [self.user_id],
            }
        }])

    @defer.inlineCallbacks
    def test_set_not_typing(self):
        (code, _) = yield self.mock_resource.trigger(
            "PUT", "/rooms/%s/typing/%s" % (self.room_id, self.user_id),
            '{"typing": false}'
        )
        self.assertEquals(200, code)

    @defer.inlineCallbacks
    def test_typing_timeout(self):
        (code, _) = yield self.mock_resource.trigger(
            "PUT", "/rooms/%s/typing/%s" % (self.room_id, self.user_id),
            '{"typing": true, "timeout": 30000}'
        )
        self.assertEquals(200, code)

        self.assertEquals(self.event_source.get_current_key(), 1)

        self.clock.advance_time(36)

        self.assertEquals(self.event_source.get_current_key(), 2)

        (code, _) = yield self.mock_resource.trigger(
            "PUT", "/rooms/%s/typing/%s" % (self.room_id, self.user_id),
            '{"typing": true, "timeout": 30000}'
        )
        self.assertEquals(200, code)

        self.assertEquals(self.event_source.get_current_key(), 3)
