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

"""Tests REST events for /presence paths."""

from twisted.trial import unittest
from twisted.internet import defer

from mock import Mock
import logging

from ..utils import MockHttpServer

from synapse.api.constants import PresenceState
from synapse.server import HomeServer


logging.getLogger().addHandler(logging.NullHandler())


OFFLINE = PresenceState.OFFLINE
BUSY = PresenceState.BUSY
ONLINE = PresenceState.ONLINE


myid = "@apple:test"
PATH_PREFIX = "/matrix/client/api/v1"


class PresenceStateTestCase(unittest.TestCase):

    def setUp(self):
        self.mock_server = MockHttpServer(prefix=PATH_PREFIX)
        self.mock_handler = Mock(spec=[
            "get_state",
            "set_state",
        ])

        hs = HomeServer("test",
            db_pool=None,
            http_client=None,
            http_server=self.mock_server,
        )

        def _get_user_by_token(token=None):
            return hs.parse_userid(myid)

        hs.get_auth().get_user_by_token = _get_user_by_token

        hs.get_handlers().presence_handler = self.mock_handler

        hs.register_servlets()

        self.u_apple = hs.parse_userid(myid)

    @defer.inlineCallbacks
    def test_get_my_status(self):
        mocked_get = self.mock_handler.get_state
        mocked_get.return_value = defer.succeed(
                {"state": 2, "status_msg": "Available"})

        (code, response) = yield self.mock_server.trigger("GET",
                "/presence/%s/status" % (myid), None)

        self.assertEquals(200, code)
        self.assertEquals({"state": ONLINE, "status_msg": "Available"},
                response)
        mocked_get.assert_called_with(target_user=self.u_apple,
                auth_user=self.u_apple)

    @defer.inlineCallbacks
    def test_set_my_status(self):
        mocked_set = self.mock_handler.set_state
        mocked_set.return_value = defer.succeed(())

        (code, response) = yield self.mock_server.trigger("PUT",
                "/presence/%s/status" % (myid),
                '{"state": 1, "status_msg": "Away"}')

        self.assertEquals(200, code)
        mocked_set.assert_called_with(target_user=self.u_apple,
                auth_user=self.u_apple,
                state={"state": 1, "status_msg": "Away"})


class PresenceListTestCase(unittest.TestCase):

    def setUp(self):
        self.mock_server = MockHttpServer(prefix=PATH_PREFIX)
        self.mock_handler = Mock(spec=[
            "get_presence_list",
            "send_invite",
            "drop",
        ])

        hs = HomeServer("test",
            db_pool=None,
            http_client=None,
            http_server=self.mock_server,
        )

        def _get_user_by_token(token=None):
            return hs.parse_userid(myid)

        hs.get_auth().get_user_by_token = _get_user_by_token

        hs.get_handlers().presence_handler = self.mock_handler

        hs.register_servlets()

        self.u_apple = hs.parse_userid("@apple:test")
        self.u_banana = hs.parse_userid("@banana:test")

    @defer.inlineCallbacks
    def test_get_my_list(self):
        self.mock_handler.get_presence_list.return_value = defer.succeed(
                [{"observed_user": self.u_banana}]
        )

        (code, response) = yield self.mock_server.trigger("GET",
                "/presence_list/%s" % (myid), None)

        self.assertEquals(200, code)
        self.assertEquals([{"user_id": "@banana:test"}], response)

    @defer.inlineCallbacks
    def test_invite(self):
        self.mock_handler.send_invite.return_value = defer.succeed(())

        (code, response) = yield self.mock_server.trigger("POST",
                "/presence_list/%s" % (myid),
                """{
                    "invite": ["@banana:test"]
                }""")

        self.assertEquals(200, code)

        self.mock_handler.send_invite.assert_called_with(
                observer_user=self.u_apple, observed_user=self.u_banana)

    @defer.inlineCallbacks
    def test_drop(self):
        self.mock_handler.drop.return_value = defer.succeed(())

        (code, response) = yield self.mock_server.trigger("POST",
                "/presence_list/%s" % (myid),
                """{
                    "drop": ["@banana:test"]
                }""")

        self.assertEquals(200, code)

        self.mock_handler.drop.assert_called_with(
                observer_user=self.u_apple, observed_user=self.u_banana)


class PresenceEventStreamTestCase(unittest.TestCase):
    def setUp(self):
        self.mock_server = MockHttpServer(prefix=PATH_PREFIX)

        # TODO: mocked data store

        # HIDEOUS HACKERY
        # TODO(paul): This should be injected in via the HomeServer DI system
        from synapse.handlers.events import EventStreamHandler
        from synapse.handlers.presence import PresenceStreamData
        EventStreamHandler.stream_data_classes = [
            PresenceStreamData
        ]

        hs = HomeServer("test",
            db_pool=None,
            http_client=None,
            http_server=self.mock_server,
            datastore=Mock(spec=[
                "set_presence_state",
                "get_presence_list",
            ]),
            clock=Mock(spec=[
                "call_later",
                "cancel_call_later",
                "time_msec",
            ]),
        )

        hs.get_clock().time_msec.return_value = 1000000

        def _get_user_by_req(req=None):
            return hs.parse_userid(myid)

        hs.get_auth().get_user_by_req = _get_user_by_req

        hs.register_servlets()

        hs.handlers.room_member_handler = Mock(spec=[
            "get_rooms_for_user",
        ])
        hs.handlers.room_member_handler.get_rooms_for_user = (
                lambda u: defer.succeed([]))

        self.mock_datastore = hs.get_datastore()
        self.presence = hs.get_handlers().presence_handler

        self.u_apple = hs.parse_userid("@apple:test")
        self.u_banana = hs.parse_userid("@banana:test")

    @defer.inlineCallbacks
    def test_shortpoll(self):
        self.mock_datastore.set_presence_state.return_value = defer.succeed(
                {"state": ONLINE})
        self.mock_datastore.get_presence_list.return_value = defer.succeed(
                [])

        (code, response) = yield self.mock_server.trigger("GET",
                "/events?timeout=0", None)

        self.assertEquals(200, code)

        # We've forced there to be only one data stream so the tokens will
        # all be ours

        # I'll already get my own presence state change
        self.assertEquals({"start": "0", "end": "1", "chunk": [
            {"type": "m.presence",
             "content": {"user_id": "@apple:test", "state": 2}},
        ]}, response)

        self.mock_datastore.set_presence_state.return_value = defer.succeed(
                {"state": ONLINE})
        self.mock_datastore.get_presence_list.return_value = defer.succeed(
                [])

        yield self.presence.set_state(self.u_banana, self.u_banana,
                state={"state": ONLINE})

        (code, response) = yield self.mock_server.trigger("GET",
                "/events?from=1&timeout=0", None)

        self.assertEquals(200, code)
        self.assertEquals({"start": "1", "end": "2", "chunk": [
            {"type": "m.presence",
             "content": {"user_id": "@banana:test", "state": 2}},
        ]}, response)
