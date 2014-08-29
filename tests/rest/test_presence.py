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

from ..utils import MockHttpResource

from synapse.api.constants import PresenceState
from synapse.handlers.presence import PresenceHandler
from synapse.server import HomeServer


logging.getLogger().addHandler(logging.NullHandler())


OFFLINE = PresenceState.OFFLINE
UNAVAILABLE = PresenceState.UNAVAILABLE
ONLINE = PresenceState.ONLINE


myid = "@apple:test"
PATH_PREFIX = "/matrix/client/api/v1"


class JustPresenceHandlers(object):
    def __init__(self, hs):
        self.presence_handler = PresenceHandler(hs)


class PresenceStateTestCase(unittest.TestCase):

    def setUp(self):
        self.mock_resource = MockHttpResource(prefix=PATH_PREFIX)

        hs = HomeServer("test",
            db_pool=None,
            datastore=Mock(spec=[
                "get_presence_state",
                "set_presence_state",
            ]),
            http_client=None,
            resource_for_client=self.mock_resource,
            resource_for_federation=self.mock_resource,
        )
        hs.handlers = JustPresenceHandlers(hs)

        self.datastore = hs.get_datastore()

        def get_presence_list(*a, **kw):
            return defer.succeed([])
        self.datastore.get_presence_list = get_presence_list

        def _get_user_by_token(token=None):
            return hs.parse_userid(myid)

        hs.get_auth().get_user_by_token = _get_user_by_token

        room_member_handler = hs.handlers.room_member_handler = Mock(
            spec=[
                "get_rooms_for_user",
            ]
        )

        def get_rooms_for_user(user):
            return defer.succeed([])
        room_member_handler.get_rooms_for_user = get_rooms_for_user

        hs.register_servlets()

        self.u_apple = hs.parse_userid(myid)

    @defer.inlineCallbacks
    def test_get_my_status(self):
        mocked_get = self.datastore.get_presence_state
        mocked_get.return_value = defer.succeed(
            {"state": ONLINE, "status_msg": "Available"}
        )

        (code, response) = yield self.mock_resource.trigger("GET",
                "/presence/%s/status" % (myid), None)

        self.assertEquals(200, code)
        self.assertEquals({"state": ONLINE, "status_msg": "Available"},
                response)
        mocked_get.assert_called_with("apple")

    @defer.inlineCallbacks
    def test_set_my_status(self):
        mocked_set = self.datastore.set_presence_state
        mocked_set.return_value = defer.succeed({"state": OFFLINE})

        (code, response) = yield self.mock_resource.trigger("PUT",
                "/presence/%s/status" % (myid),
                '{"state": "unavailable", "status_msg": "Away"}')

        self.assertEquals(200, code)
        mocked_set.assert_called_with("apple",
                {"state": UNAVAILABLE, "status_msg": "Away"})


class PresenceListTestCase(unittest.TestCase):

    def setUp(self):
        self.mock_resource = MockHttpResource(prefix=PATH_PREFIX)

        hs = HomeServer("test",
            db_pool=None,
            datastore=Mock(spec=[
                "has_presence_state",
                "get_presence_state",
                "allow_presence_visible",
                "is_presence_visible",
                "add_presence_list_pending",
                "set_presence_list_accepted",
                "del_presence_list",
                "get_presence_list",
            ]),
            http_client=None,
            resource_for_client=self.mock_resource,
            resource_for_federation=self.mock_resource
        )
        hs.handlers = JustPresenceHandlers(hs)

        self.datastore = hs.get_datastore()

        def has_presence_state(user_localpart):
            return defer.succeed(
                user_localpart in ("apple", "banana",)
            )
        self.datastore.has_presence_state = has_presence_state

        def _get_user_by_token(token=None):
            return hs.parse_userid(myid)

        room_member_handler = hs.handlers.room_member_handler = Mock(
            spec=[
                "get_rooms_for_user",
            ]
        )

        hs.get_auth().get_user_by_token = _get_user_by_token

        hs.register_servlets()

        self.u_apple = hs.parse_userid("@apple:test")
        self.u_banana = hs.parse_userid("@banana:test")

    @defer.inlineCallbacks
    def test_get_my_list(self):
        self.datastore.get_presence_list.return_value = defer.succeed(
            [{"observed_user_id": "@banana:test"}],
        )

        (code, response) = yield self.mock_resource.trigger("GET",
                "/presence/list/%s" % (myid), None)

        self.assertEquals(200, code)
        self.assertEquals(
            [{"user_id": "@banana:test", "state": OFFLINE}], response
        )

        self.datastore.get_presence_list.assert_called_with(
            "apple", accepted=True
        )

    @defer.inlineCallbacks
    def test_invite(self):
        self.datastore.add_presence_list_pending.return_value = (
            defer.succeed(())
        )
        self.datastore.is_presence_visible.return_value = defer.succeed(
            True
        )

        (code, response) = yield self.mock_resource.trigger("POST",
            "/presence/list/%s" % (myid),
            """{"invite": ["@banana:test"]}"""
        )

        self.assertEquals(200, code)

        self.datastore.add_presence_list_pending.assert_called_with(
            "apple", "@banana:test"
        )
        self.datastore.set_presence_list_accepted.assert_called_with(
            "apple", "@banana:test"
        )

    @defer.inlineCallbacks
    def test_drop(self):
        self.datastore.del_presence_list.return_value = (
            defer.succeed(())
        )

        (code, response) = yield self.mock_resource.trigger("POST",
            "/presence/list/%s" % (myid),
            """{"drop": ["@banana:test"]}"""
        )

        self.assertEquals(200, code)

        self.datastore.del_presence_list.assert_called_with(
            "apple", "@banana:test"
        )


class PresenceEventStreamTestCase(unittest.TestCase):
    def setUp(self):
        self.mock_resource = MockHttpResource(prefix=PATH_PREFIX)

        # HIDEOUS HACKERY
        # TODO(paul): This should be injected in via the HomeServer DI system
        from synapse.streams.events import (
            PresenceEventSource, NullSource, EventSources
        )

        old_SOURCE_TYPES = EventSources.SOURCE_TYPES
        def tearDown():
            EventSources.SOURCE_TYPES = old_SOURCE_TYPES
        self.tearDown = tearDown

        EventSources.SOURCE_TYPES = {
            k: NullSource for k in old_SOURCE_TYPES.keys()
        }
        EventSources.SOURCE_TYPES["presence"] = PresenceEventSource

        hs = HomeServer("test",
            db_pool=None,
            http_client=None,
            resource_for_client=self.mock_resource,
            resource_for_federation=self.mock_resource,
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

        (code, response) = yield self.mock_resource.trigger("GET",
                "/events?timeout=0", None)

        self.assertEquals(200, code)

        # We've forced there to be only one data stream so the tokens will
        # all be ours

        # I'll already get my own presence state change
        self.assertEquals({"start": "0_1", "end": "0_1", "chunk": []}, response)

        self.mock_datastore.set_presence_state.return_value = defer.succeed(
                {"state": ONLINE})
        self.mock_datastore.get_presence_list.return_value = defer.succeed(
                [])

        yield self.presence.set_state(self.u_banana, self.u_banana,
                state={"state": ONLINE})

        (code, response) = yield self.mock_resource.trigger("GET",
                "/events?from=0_1&timeout=0", None)

        self.assertEquals(200, code)
        self.assertEquals({"start": "0_1", "end": "0_2", "chunk": [
            {"type": "m.presence",
             "content": {
                 "user_id": "@banana:test",
                 "state": ONLINE,
                 "mtime_age": 0,
            }},
        ]}, response)
