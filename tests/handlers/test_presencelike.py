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

"""This file contains tests of the "presence-like" data that is shared between
presence and profiles; namely, the displayname and avatar_url."""

from tests import unittest
from twisted.internet import defer

from mock import Mock, call, ANY, NonCallableMock

from ..utils import MockClock, setup_test_homeserver

from synapse.api.constants import PresenceState
from synapse.handlers.presence import PresenceHandler
from synapse.handlers.profile import ProfileHandler
from synapse.types import UserID


OFFLINE = PresenceState.OFFLINE
UNAVAILABLE = PresenceState.UNAVAILABLE
ONLINE = PresenceState.ONLINE


class MockReplication(object):
    def __init__(self):
        self.edu_handlers = {}

    def register_edu_handler(self, edu_type, handler):
        self.edu_handlers[edu_type] = handler

    def register_query_handler(self, query_type, handler):
        pass

    def received_edu(self, origin, edu_type, content):
        self.edu_handlers[edu_type](origin, content)


class PresenceAndProfileHandlers(object):
    def __init__(self, hs):
        self.presence_handler = PresenceHandler(hs)
        self.profile_handler = ProfileHandler(hs)


class PresenceProfilelikeDataTestCase(unittest.TestCase):

    @defer.inlineCallbacks
    def setUp(self):
        hs = yield setup_test_homeserver(
            clock=MockClock(),
            datastore=Mock(spec=[
                "set_presence_state",
                "is_presence_visible",
                "set_profile_displayname",
                "get_rooms_for_user_where_membership_is",
            ]),
            handlers=None,
            resource_for_federation=Mock(),
            http_client=None,
            replication_layer=MockReplication(),
            ratelimiter=NonCallableMock(spec_set=[
                "send_message",
            ]),
        )
        self.ratelimiter = hs.get_ratelimiter()
        self.ratelimiter.send_message.return_value = (True, 0)
        hs.handlers = PresenceAndProfileHandlers(hs)

        self.datastore = hs.get_datastore()

        self.replication = hs.get_replication_layer()
        self.replication.send_edu = Mock()

        def send_edu(*args, **kwargs):
            # print "send_edu: %s, %s" % (args, kwargs)
            return defer.succeed((200, "OK"))
        self.replication.send_edu.side_effect = send_edu

        def get_profile_displayname(user_localpart):
            return defer.succeed("Frank")
        self.datastore.get_profile_displayname = get_profile_displayname

        def is_presence_visible(*args, **kwargs):
            return defer.succeed(False)
        self.datastore.is_presence_visible = is_presence_visible

        def get_profile_avatar_url(user_localpart):
            return defer.succeed("http://foo")
        self.datastore.get_profile_avatar_url = get_profile_avatar_url

        self.presence_list = [
            {"observed_user_id": "@banana:test"},
            {"observed_user_id": "@clementine:test"},
        ]
        def get_presence_list(user_localpart, accepted=None):
            return defer.succeed(self.presence_list)
        self.datastore.get_presence_list = get_presence_list

        def user_rooms_intersect(userlist):
            return defer.succeed(False)
        self.datastore.user_rooms_intersect = user_rooms_intersect

        self.handlers = hs.get_handlers()

        self.mock_update_client = Mock()
        def update(*args, **kwargs):
            # print "mock_update_client: %s, %s" %(args, kwargs)
            return defer.succeed(None)
        self.mock_update_client.side_effect = update

        self.handlers.presence_handler.push_update_to_clients = (
                self.mock_update_client)

        hs.handlers.room_member_handler = Mock(spec=[
            "get_rooms_for_user",
        ])
        hs.handlers.room_member_handler.get_rooms_for_user = (
                lambda u: defer.succeed([]))

        # Some local users to test with
        self.u_apple = UserID.from_string("@apple:test")
        self.u_banana = UserID.from_string("@banana:test")
        self.u_clementine = UserID.from_string("@clementine:test")

        # Remote user
        self.u_potato = UserID.from_string("@potato:remote")

        self.mock_get_joined = (
            self.datastore.get_rooms_for_user_where_membership_is
        )

    @defer.inlineCallbacks
    def test_set_my_state(self):
        self.presence_list = [
            {"observed_user_id": "@banana:test"},
            {"observed_user_id": "@clementine:test"},
        ]

        mocked_set = self.datastore.set_presence_state
        mocked_set.return_value = defer.succeed({"state": OFFLINE})

        yield self.handlers.presence_handler.set_state(
                target_user=self.u_apple, auth_user=self.u_apple,
                state={"presence": UNAVAILABLE, "status_msg": "Away"})

        mocked_set.assert_called_with("apple",
            {"state": UNAVAILABLE, "status_msg": "Away"}
        )

    @defer.inlineCallbacks
    def test_push_local(self):
        def get_joined(*args):
            return defer.succeed([])

        self.mock_get_joined.side_effect = get_joined

        self.presence_list = [
            {"observed_user_id": "@banana:test"},
            {"observed_user_id": "@clementine:test"},
        ]

        self.datastore.set_presence_state.return_value = defer.succeed(
            {"state": ONLINE}
        )

        # TODO(paul): Gut-wrenching
        from synapse.handlers.presence import UserPresenceCache
        self.handlers.presence_handler._user_cachemap[self.u_apple] = (
            UserPresenceCache()
        )
        self.handlers.presence_handler._user_cachemap[self.u_apple].update(
            {"presence": OFFLINE}, serial=0
        )
        apple_set = self.handlers.presence_handler._local_pushmap.setdefault(
                "apple", set())
        apple_set.add(self.u_banana)
        apple_set.add(self.u_clementine)

        yield self.handlers.presence_handler.set_state(self.u_apple,
            self.u_apple, {"presence": ONLINE}
        )
        yield self.handlers.presence_handler.set_state(self.u_banana,
            self.u_banana, {"presence": ONLINE}
        )

        presence = yield self.handlers.presence_handler.get_presence_list(
                observer_user=self.u_apple, accepted=True)

        self.assertEquals([
            {"observed_user": self.u_banana,
                "presence": ONLINE,
                "last_active_ago": 0,
                "displayname": "Frank",
                "avatar_url": "http://foo"},
            {"observed_user": self.u_clementine,
                "presence": OFFLINE}
        ], presence)

        self.mock_update_client.assert_has_calls([
            call(users_to_push=set([self.u_apple, self.u_banana, self.u_clementine]),
                room_ids=[],
                observed_user=self.u_apple,
                statuscache=ANY), # self-reflection
        ], any_order=True)

        statuscache = self.mock_update_client.call_args[1]["statuscache"]
        self.assertEquals({
            "presence": ONLINE,
            "last_active": 1000000, # MockClock
            "displayname": "Frank",
            "avatar_url": "http://foo",
        }, statuscache.state)

        self.mock_update_client.reset_mock()

        self.datastore.set_profile_displayname.return_value = defer.succeed(
                None)

        yield self.handlers.profile_handler.set_displayname(self.u_apple,
                self.u_apple, "I am an Apple")

        self.mock_update_client.assert_has_calls([
            call(users_to_push=set([self.u_apple, self.u_banana, self.u_clementine]),
                room_ids=[],
                observed_user=self.u_apple,
                statuscache=ANY), # self-reflection
        ], any_order=True)

        statuscache = self.mock_update_client.call_args[1]["statuscache"]
        self.assertEquals({
            "presence": ONLINE,
            "last_active": 1000000, # MockClock
            "displayname": "I am an Apple",
            "avatar_url": "http://foo",
        }, statuscache.state)


    @defer.inlineCallbacks
    def test_push_remote(self):
        self.presence_list = [
            {"observed_user_id": "@potato:remote"},
        ]

        self.datastore.set_presence_state.return_value = defer.succeed(
            {"state": ONLINE}
        )

        # TODO(paul): Gut-wrenching
        from synapse.handlers.presence import UserPresenceCache
        self.handlers.presence_handler._user_cachemap[self.u_apple] = (
            UserPresenceCache()
        )
        self.handlers.presence_handler._user_cachemap[self.u_apple].update(
            {"presence": OFFLINE}, serial=0
        )
        apple_set = self.handlers.presence_handler._remote_sendmap.setdefault(
                "apple", set())
        apple_set.add(self.u_potato.domain)

        yield self.handlers.presence_handler.set_state(self.u_apple,
            self.u_apple, {"presence": ONLINE}
        )

        self.replication.send_edu.assert_called_with(
                destination="remote",
                edu_type="m.presence",
                content={
                    "push": [
                        {"user_id": "@apple:test",
                         "presence": "online",
                         "last_active_ago": 0,
                         "displayname": "Frank",
                         "avatar_url": "http://foo"},
                    ],
                },
        )

    @defer.inlineCallbacks
    def test_recv_remote(self):
        self.presence_list = [
            {"observed_user_id": "@banana:test"},
            {"observed_user_id": "@clementine:test"},
        ]

        # TODO(paul): Gut-wrenching
        potato_set = self.handlers.presence_handler._remote_recvmap.setdefault(
            self.u_potato, set()
        )
        potato_set.add(self.u_apple)

        yield self.replication.received_edu(
            "remote", "m.presence", {
                "push": [
                    {"user_id": "@potato:remote",
                     "presence": "online",
                     "displayname": "Frank",
                     "avatar_url": "http://foo"},
                ],
            }
        )

        self.mock_update_client.assert_called_with(
            users_to_push=set([self.u_apple]),
            room_ids=[],
            observed_user=self.u_potato,
            statuscache=ANY)

        statuscache = self.mock_update_client.call_args[1]["statuscache"]
        self.assertEquals({"presence": ONLINE,
                           "displayname": "Frank",
                           "avatar_url": "http://foo"}, statuscache.state)

        state = yield self.handlers.presence_handler.get_state(self.u_potato,
                self.u_apple)

        self.assertEquals(
                {"presence": ONLINE,
                 "displayname": "Frank",
                 "avatar_url": "http://foo"},
            state)
