# -*- coding: utf-8 -*-
# Copyright 2014 matrix.org
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

from twisted.trial import unittest
from twisted.internet import defer

from mock import Mock, call, ANY
import logging

from synapse.server import HomeServer
from synapse.api.constants import PresenceState
from synapse.handlers.presence import PresenceHandler
from synapse.handlers.profile import ProfileHandler


OFFLINE = PresenceState.OFFLINE
UNAVAILABLE = PresenceState.UNAVAILABLE
ONLINE = PresenceState.ONLINE


logging.getLogger().addHandler(logging.NullHandler())


class MockReplication(object):
    def __init__(self):
        self.edu_handlers = {}

    def register_edu_handler(self, edu_type, handler):
        self.edu_handlers[edu_type] = handler

    def received_edu(self, origin, edu_type, content):
        self.edu_handlers[edu_type](origin, content)


class PresenceAndProfileHandlers(object):
    def __init__(self, hs):
        self.presence_handler = PresenceHandler(hs)
        self.profile_handler = ProfileHandler(hs)


class PresenceProfilelikeDataTestCase(unittest.TestCase):

    def setUp(self):
        hs = HomeServer("test",
                db_pool=None,
                datastore=Mock(spec=[
                    "set_presence_state",

                    "set_profile_displayname",
                ]),
                handlers=None,
                http_server=Mock(),
                http_client=None,
                replication_layer=MockReplication(),
            )
        hs.handlers = PresenceAndProfileHandlers(hs)

        self.datastore = hs.get_datastore()

        self.replication = hs.get_replication_layer()
        self.replication.send_edu = Mock()
        self.replication.send_edu.return_value = defer.succeed((200, "OK"))

        def get_profile_displayname(user_localpart):
            return defer.succeed("Frank")
        self.datastore.get_profile_displayname = get_profile_displayname

        def get_profile_avatar_url(user_localpart):
            return defer.succeed("http://foo")
        self.datastore.get_profile_avatar_url = get_profile_avatar_url

        def get_presence_list(user_localpart, accepted=None):
            return defer.succeed([
                {"observed_user_id": "@banana:test"},
                {"observed_user_id": "@clementine:test"},
            ])
        self.datastore.get_presence_list = get_presence_list

        self.handlers = hs.get_handlers()

        self.mock_start = Mock()
        self.mock_stop = Mock()

        self.mock_update_client = Mock()
        self.mock_update_client.return_value = defer.succeed(None)

        self.handlers.presence_handler.start_polling_presence = self.mock_start
        self.handlers.presence_handler.stop_polling_presence = self.mock_stop
        self.handlers.presence_handler.push_update_to_clients = (
                self.mock_update_client)

        hs.handlers.room_member_handler = Mock(spec=[
            "get_rooms_for_user",
        ])
        hs.handlers.room_member_handler.get_rooms_for_user = (
                lambda u: defer.succeed([]))

        # Some local users to test with
        self.u_apple = hs.parse_userid("@apple:test")
        self.u_banana = hs.parse_userid("@banana:test")
        self.u_clementine = hs.parse_userid("@clementine:test")

        # Remote user
        self.u_potato = hs.parse_userid("@potato:remote")

    @defer.inlineCallbacks
    def test_set_my_state(self):
        mocked_set = self.datastore.set_presence_state
        mocked_set.return_value = defer.succeed({"state": OFFLINE})

        yield self.handlers.presence_handler.set_state(
                target_user=self.u_apple, auth_user=self.u_apple,
                state={"state": UNAVAILABLE, "status_msg": "Away"})

        mocked_set.assert_called_with("apple",
                {"state": UNAVAILABLE, "status_msg": "Away"})
        self.mock_start.assert_called_with(self.u_apple,
                state={"state": UNAVAILABLE, "status_msg": "Away",
                       "displayname": "Frank",
                       "avatar_url": "http://foo"})

    @defer.inlineCallbacks
    def test_push_local(self):
        self.datastore.set_presence_state.return_value = defer.succeed(
                {"state": ONLINE})

        # TODO(paul): Gut-wrenching
        from synapse.handlers.presence import UserPresenceCache
        self.handlers.presence_handler._user_cachemap[self.u_apple] = (
                UserPresenceCache())
        apple_set = self.handlers.presence_handler._local_pushmap.setdefault(
                "apple", set())
        apple_set.add(self.u_banana)
        apple_set.add(self.u_clementine)

        yield self.handlers.presence_handler.set_state(self.u_apple,
                self.u_apple, {"state": ONLINE})
        yield self.handlers.presence_handler.set_state(self.u_banana,
                self.u_banana, {"state": ONLINE})

        presence = yield self.handlers.presence_handler.get_presence_list(
                observer_user=self.u_apple, accepted=True)

        self.assertEquals([
                {"observed_user": self.u_banana, "state": ONLINE,
                    "displayname": "Frank", "avatar_url": "http://foo"},
                {"observed_user": self.u_clementine, "state": OFFLINE}],
            presence)

        self.mock_update_client.assert_has_calls([
            call(observer_user=self.u_apple,
                observed_user=self.u_apple,
                statuscache=ANY), # self-reflection
            call(observer_user=self.u_banana,
                observed_user=self.u_apple,
                statuscache=ANY),
        ], any_order=True)

        statuscache = self.mock_update_client.call_args[1]["statuscache"]
        self.assertEquals({"state": ONLINE,
                           "displayname": "Frank",
                           "avatar_url": "http://foo"}, statuscache.state)

        self.mock_update_client.reset_mock()

        self.datastore.set_profile_displayname.return_value = defer.succeed(
                None)

        yield self.handlers.profile_handler.set_displayname(self.u_apple,
                self.u_apple, "I am an Apple")

        self.mock_update_client.assert_has_calls([
            call(observer_user=self.u_apple,
                observed_user=self.u_apple,
                statuscache=ANY), # self-reflection
            call(observer_user=self.u_banana,
                observed_user=self.u_apple,
                statuscache=ANY),
        ], any_order=True)

        statuscache = self.mock_update_client.call_args[1]["statuscache"]
        self.assertEquals({"state": ONLINE,
                           "displayname": "I am an Apple",
                           "avatar_url": "http://foo"}, statuscache.state)

    @defer.inlineCallbacks
    def test_push_remote(self):
        self.datastore.set_presence_state.return_value = defer.succeed(
                {"state": ONLINE})

        # TODO(paul): Gut-wrenching
        from synapse.handlers.presence import UserPresenceCache
        self.handlers.presence_handler._user_cachemap[self.u_apple] = (
                UserPresenceCache())
        apple_set = self.handlers.presence_handler._remote_sendmap.setdefault(
                "apple", set())
        apple_set.add(self.u_potato.domain)

        yield self.handlers.presence_handler.set_state(self.u_apple,
                self.u_apple, {"state": ONLINE})

        self.replication.send_edu.assert_called_with(
                destination="remote",
                edu_type="m.presence",
                content={
                    "push": [
                        {"user_id": "@apple:test",
                         "state": "online",
                         "displayname": "Frank",
                         "avatar_url": "http://foo"},
                    ],
                },
        )

    @defer.inlineCallbacks
    def test_recv_remote(self):
        # TODO(paul): Gut-wrenching
        potato_set = self.handlers.presence_handler._remote_recvmap.setdefault(
                self.u_potato, set())
        potato_set.add(self.u_apple)

        yield self.replication.received_edu(
                "remote", "m.presence", {
                    "push": [
                        {"user_id": "@potato:remote",
                         "state": "online",
                         "displayname": "Frank",
                         "avatar_url": "http://foo"},
                    ],
                }
        )

        self.mock_update_client.assert_called_with(
            observer_user=self.u_apple,
            observed_user=self.u_potato,
            statuscache=ANY)

        statuscache = self.mock_update_client.call_args[1]["statuscache"]
        self.assertEquals({"state": ONLINE,
                           "displayname": "Frank",
                           "avatar_url": "http://foo"}, statuscache.state)

        state = yield self.handlers.presence_handler.get_state(self.u_potato,
                self.u_apple)

        self.assertEquals({"state": ONLINE,
                           "displayname": "Frank",
                           "avatar_url": "http://foo"},
                state)
