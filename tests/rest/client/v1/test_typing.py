# -*- coding: utf-8 -*-
# Copyright 2014-2016 OpenMarket Ltd
# Copyright 2018 New Vector
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

from mock import Mock

from twisted.internet import defer

from synapse.rest.client.v1 import room
from synapse.types import UserID

from tests import unittest

PATH_PREFIX = "/_matrix/client/api/v1"


class RoomTypingTestCase(unittest.HomeserverTestCase):
    """ Tests /rooms/$room_id/typing/$user_id REST API. """

    user_id = "@sid:red"

    user = UserID.from_string(user_id)
    servlets = [room.register_servlets]

    def make_homeserver(self, reactor, clock):

        hs = self.setup_test_homeserver(
            "red", http_client=None, federation_client=Mock(),
        )

        self.event_source = hs.get_event_sources().sources["typing"]

        hs.get_handlers().federation_handler = Mock()

        async def get_user_by_access_token(token=None, allow_guest=False):
            return {
                "user": UserID.from_string(self.auth_user_id),
                "token_id": 1,
                "is_guest": False,
            }

        hs.get_auth().get_user_by_access_token = get_user_by_access_token

        async def _insert_client_ip(*args, **kwargs):
            return None

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

        hs.get_room_member_handler().fetch_room_distributions_into = (
            fetch_room_distributions_into
        )

        return hs

    def prepare(self, reactor, clock, hs):
        self.room_id = self.helper.create_room_as(self.user_id)
        # Need another user to make notifications actually work
        self.helper.join(self.room_id, user="@jim:red")

    def test_set_typing(self):
        request, channel = self.make_request(
            "PUT",
            "/rooms/%s/typing/%s" % (self.room_id, self.user_id),
            b'{"typing": true, "timeout": 30000}',
        )
        self.render(request)
        self.assertEquals(200, channel.code)

        self.assertEquals(self.event_source.get_current_key(), 1)
        events = self.get_success(
            self.event_source.get_new_events(from_key=0, room_ids=[self.room_id])
        )
        self.assertEquals(
            events[0],
            [
                {
                    "type": "m.typing",
                    "room_id": self.room_id,
                    "content": {"user_ids": [self.user_id]},
                }
            ],
        )

    def test_set_not_typing(self):
        request, channel = self.make_request(
            "PUT",
            "/rooms/%s/typing/%s" % (self.room_id, self.user_id),
            b'{"typing": false}',
        )
        self.render(request)
        self.assertEquals(200, channel.code)

    def test_typing_timeout(self):
        request, channel = self.make_request(
            "PUT",
            "/rooms/%s/typing/%s" % (self.room_id, self.user_id),
            b'{"typing": true, "timeout": 30000}',
        )
        self.render(request)
        self.assertEquals(200, channel.code)

        self.assertEquals(self.event_source.get_current_key(), 1)

        self.reactor.advance(36)

        self.assertEquals(self.event_source.get_current_key(), 2)

        request, channel = self.make_request(
            "PUT",
            "/rooms/%s/typing/%s" % (self.room_id, self.user_id),
            b'{"typing": true, "timeout": 30000}',
        )
        self.render(request)
        self.assertEquals(200, channel.code)

        self.assertEquals(self.event_source.get_current_key(), 3)
