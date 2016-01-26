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

"""Tests REST events for /presence paths."""
from tests import unittest
from twisted.internet import defer

from mock import Mock

from ....utils import MockHttpResource, setup_test_homeserver

from synapse.api.constants import PresenceState
from synapse.handlers.presence import PresenceHandler
from synapse.rest.client.v1 import presence
from synapse.rest.client.v1 import events
from synapse.types import Requester, UserID
from synapse.util.async import run_on_reactor

from collections import namedtuple


OFFLINE = PresenceState.OFFLINE
UNAVAILABLE = PresenceState.UNAVAILABLE
ONLINE = PresenceState.ONLINE


myid = "@apple:test"
PATH_PREFIX = "/_matrix/client/api/v1"


class NullSource(object):
    """This event source never yields any events and its token remains at
    zero. It may be useful for unit-testing."""
    def __init__(self, hs):
        pass

    def get_new_events(
            self,
            user,
            from_key,
            room_ids=None,
            limit=None,
            is_guest=None
    ):
        return defer.succeed(([], from_key))

    def get_current_key(self, direction='f'):
        return defer.succeed(0)

    def get_pagination_rows(self, user, pagination_config, key):
        return defer.succeed(([], pagination_config.from_key))


class JustPresenceHandlers(object):
    def __init__(self, hs):
        self.presence_handler = PresenceHandler(hs)


class PresenceStateTestCase(unittest.TestCase):

    @defer.inlineCallbacks
    def setUp(self):
        self.mock_resource = MockHttpResource(prefix=PATH_PREFIX)
        hs = yield setup_test_homeserver(
            datastore=Mock(spec=[
                "get_presence_state",
                "set_presence_state",
                "insert_client_ip",
            ]),
            http_client=None,
            resource_for_client=self.mock_resource,
            resource_for_federation=self.mock_resource,
        )
        hs.handlers = JustPresenceHandlers(hs)

        self.datastore = hs.get_datastore()
        self.datastore.get_app_service_by_token = Mock(return_value=None)

        def get_presence_list(*a, **kw):
            return defer.succeed([])
        self.datastore.get_presence_list = get_presence_list

        def _get_user_by_access_token(token=None, allow_guest=False):
            return {
                "user": UserID.from_string(myid),
                "token_id": 1,
                "is_guest": False,
            }

        hs.get_v1auth()._get_user_by_access_token = _get_user_by_access_token

        room_member_handler = hs.handlers.room_member_handler = Mock(
            spec=[
                "get_joined_rooms_for_user",
            ]
        )

        def get_rooms_for_user(user):
            return defer.succeed([])
        room_member_handler.get_joined_rooms_for_user = get_rooms_for_user

        presence.register_servlets(hs, self.mock_resource)

        self.u_apple = UserID.from_string(myid)

    @defer.inlineCallbacks
    def test_get_my_status(self):
        mocked_get = self.datastore.get_presence_state
        mocked_get.return_value = defer.succeed(
            {"state": ONLINE, "status_msg": "Available"}
        )

        (code, response) = yield self.mock_resource.trigger("GET",
                "/presence/%s/status" % (myid), None)

        self.assertEquals(200, code)
        self.assertEquals(
            {"presence": ONLINE, "status_msg": "Available"},
            response
        )
        mocked_get.assert_called_with("apple")

    @defer.inlineCallbacks
    def test_set_my_status(self):
        mocked_set = self.datastore.set_presence_state
        mocked_set.return_value = defer.succeed({"state": OFFLINE})

        (code, response) = yield self.mock_resource.trigger("PUT",
                "/presence/%s/status" % (myid),
                '{"presence": "unavailable", "status_msg": "Away"}')

        self.assertEquals(200, code)
        mocked_set.assert_called_with("apple",
            {"state": UNAVAILABLE, "status_msg": "Away"}
        )


class PresenceListTestCase(unittest.TestCase):

    @defer.inlineCallbacks
    def setUp(self):
        self.mock_resource = MockHttpResource(prefix=PATH_PREFIX)

        hs = yield setup_test_homeserver(
            datastore=Mock(spec=[
                "has_presence_state",
                "get_presence_state",
                "allow_presence_visible",
                "is_presence_visible",
                "add_presence_list_pending",
                "set_presence_list_accepted",
                "del_presence_list",
                "get_presence_list",
                "insert_client_ip",
            ]),
            http_client=None,
            resource_for_client=self.mock_resource,
            resource_for_federation=self.mock_resource,
        )
        hs.handlers = JustPresenceHandlers(hs)

        self.datastore = hs.get_datastore()
        self.datastore.get_app_service_by_token = Mock(return_value=None)

        def has_presence_state(user_localpart):
            return defer.succeed(
                user_localpart in ("apple", "banana",)
            )
        self.datastore.has_presence_state = has_presence_state

        def _get_user_by_access_token(token=None, allow_guest=False):
            return {
                "user": UserID.from_string(myid),
                "token_id": 1,
                "is_guest": False,
            }

        hs.handlers.room_member_handler = Mock(
            spec=[
                "get_joined_rooms_for_user",
            ]
        )

        hs.get_v1auth()._get_user_by_access_token = _get_user_by_access_token

        presence.register_servlets(hs, self.mock_resource)

        self.u_apple = UserID.from_string("@apple:test")
        self.u_banana = UserID.from_string("@banana:test")

    @defer.inlineCallbacks
    def test_get_my_list(self):
        self.datastore.get_presence_list.return_value = defer.succeed(
            [{"observed_user_id": "@banana:test", "accepted": True}],
        )

        (code, response) = yield self.mock_resource.trigger("GET",
                "/presence/list/%s" % (myid), None)

        self.assertEquals(200, code)
        self.assertEquals([
            {"user_id": "@banana:test", "presence": OFFLINE, "accepted": True},
        ], response)

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
    @defer.inlineCallbacks
    def setUp(self):
        self.mock_resource = MockHttpResource(prefix=PATH_PREFIX)

        # HIDEOUS HACKERY
        # TODO(paul): This should be injected in via the HomeServer DI system
        from synapse.streams.events import (
            PresenceEventSource, EventSources
        )

        old_SOURCE_TYPES = EventSources.SOURCE_TYPES
        def tearDown():
            EventSources.SOURCE_TYPES = old_SOURCE_TYPES
        self.tearDown = tearDown

        EventSources.SOURCE_TYPES = {
            k: NullSource for k in old_SOURCE_TYPES.keys()
        }
        EventSources.SOURCE_TYPES["presence"] = PresenceEventSource

        clock = Mock(spec=[
            "call_later",
            "cancel_call_later",
            "time_msec",
            "looping_call",
        ])

        clock.time_msec.return_value = 1000000

        hs = yield setup_test_homeserver(
            http_client=None,
            resource_for_client=self.mock_resource,
            resource_for_federation=self.mock_resource,
            datastore=Mock(spec=[
                "set_presence_state",
                "get_presence_list",
                "get_rooms_for_user",
            ]),
            clock=clock,
        )

        def _get_user_by_req(req=None, allow_guest=False):
            return Requester(UserID.from_string(myid), "", False)

        hs.get_v1auth().get_user_by_req = _get_user_by_req

        presence.register_servlets(hs, self.mock_resource)
        events.register_servlets(hs, self.mock_resource)

        hs.handlers.room_member_handler = Mock(spec=[])

        self.room_members = []

        def get_rooms_for_user(user):
            if user in self.room_members:
                return ["a-room"]
            else:
                return []
        hs.handlers.room_member_handler.get_joined_rooms_for_user = get_rooms_for_user
        hs.handlers.room_member_handler.get_room_members = (
            lambda r: self.room_members if r == "a-room" else []
        )
        hs.handlers.room_member_handler._filter_events_for_client = (
            lambda user_id, events, **kwargs: events
        )

        self.mock_datastore = hs.get_datastore()
        self.mock_datastore.get_app_service_by_token = Mock(return_value=None)
        self.mock_datastore.get_app_service_by_user_id = Mock(
            return_value=defer.succeed(None)
        )
        self.mock_datastore.get_rooms_for_user = (
            lambda u: [
                namedtuple("Room", "room_id")(r)
                for r in get_rooms_for_user(UserID.from_string(u))
            ]
        )

        def get_profile_displayname(user_id):
            return defer.succeed("Frank")
        self.mock_datastore.get_profile_displayname = get_profile_displayname

        def get_profile_avatar_url(user_id):
            return defer.succeed(None)
        self.mock_datastore.get_profile_avatar_url = get_profile_avatar_url

        def user_rooms_intersect(user_list):
            room_member_ids = map(lambda u: u.to_string(), self.room_members)

            shared = all(map(lambda i: i in room_member_ids, user_list))
            return defer.succeed(shared)
        self.mock_datastore.user_rooms_intersect = user_rooms_intersect

        def get_joined_hosts_for_room(room_id):
            return []
        self.mock_datastore.get_joined_hosts_for_room = get_joined_hosts_for_room

        self.presence = hs.get_handlers().presence_handler

        self.u_apple = UserID.from_string("@apple:test")
        self.u_banana = UserID.from_string("@banana:test")

    @defer.inlineCallbacks
    def test_shortpoll(self):
        self.room_members = [self.u_apple, self.u_banana]

        self.mock_datastore.set_presence_state.return_value = defer.succeed(
            {"state": ONLINE}
        )
        self.mock_datastore.get_presence_list.return_value = defer.succeed(
            []
        )

        (code, response) = yield self.mock_resource.trigger("GET",
                "/events?timeout=0", None)

        self.assertEquals(200, code)

        # We've forced there to be only one data stream so the tokens will
        # all be ours

        # I'll already get my own presence state change
        self.assertEquals({"start": "0_1_0_0_0", "end": "0_1_0_0_0", "chunk": []},
            response
        )

        self.mock_datastore.set_presence_state.return_value = defer.succeed(
            {"state": ONLINE}
        )
        self.mock_datastore.get_presence_list.return_value = defer.succeed([])

        yield self.presence.set_state(self.u_banana, self.u_banana,
            state={"presence": ONLINE}
        )

        yield run_on_reactor()

        (code, response) = yield self.mock_resource.trigger("GET",
                "/events?from=s0_1_0&timeout=0", None)

        self.assertEquals(200, code)
        self.assertEquals({"start": "s0_1_0_0_0", "end": "s0_2_0_0_0", "chunk": [
            {"type": "m.presence",
             "content": {
                 "user_id": "@banana:test",
                 "presence": ONLINE,
                 "displayname": "Frank",
                 "last_active_ago": 0,
            }},
        ]}, response)
