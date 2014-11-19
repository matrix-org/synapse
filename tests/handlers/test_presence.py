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
from twisted.internet import defer, reactor

from mock import Mock, call, ANY, NonCallableMock, patch
import json

from tests.utils import (
    MockHttpResource, MockClock, DeferredMockCallable, SQLiteMemoryDbPool,
    MockKey
)

from synapse.server import HomeServer
from synapse.api.constants import PresenceState
from synapse.api.errors import SynapseError
from synapse.handlers.presence import PresenceHandler, UserPresenceCache
from synapse.streams.config import SourcePaginationConfig


OFFLINE = PresenceState.OFFLINE
UNAVAILABLE = PresenceState.UNAVAILABLE
ONLINE = PresenceState.ONLINE


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


class JustPresenceHandlers(object):
    def __init__(self, hs):
        self.presence_handler = PresenceHandler(hs)

class PresenceStateTestCase(unittest.TestCase):
    """ Tests presence management. """

    @defer.inlineCallbacks
    def setUp(self):
        db_pool = SQLiteMemoryDbPool()
        yield db_pool.prepare()

        self.mock_config = NonCallableMock()
        self.mock_config.signing_key = [MockKey()]

        hs = HomeServer("test",
            clock=MockClock(),
            db_pool=db_pool,
            handlers=None,
            resource_for_federation=Mock(),
            http_client=None,
            config=self.mock_config,
            keyring=Mock(),
        )
        hs.handlers = JustPresenceHandlers(hs)

        self.store = hs.get_datastore()

        # Mock the RoomMemberHandler
        room_member_handler = Mock(spec=[])
        hs.handlers.room_member_handler = room_member_handler

        # Some local users to test with
        self.u_apple = hs.parse_userid("@apple:test")
        self.u_banana = hs.parse_userid("@banana:test")
        self.u_clementine = hs.parse_userid("@clementine:test")

        yield self.store.create_presence(self.u_apple.localpart)
        yield self.store.set_presence_state(
            self.u_apple.localpart, {"state": ONLINE, "status_msg": "Online"}
        )

        self.handler = hs.get_handlers().presence_handler

        self.room_members = []

        def get_rooms_for_user(user):
            if user in self.room_members:
                return defer.succeed(["a-room"])
            else:
                return defer.succeed([])
        room_member_handler.get_rooms_for_user = get_rooms_for_user

        def get_room_members(room_id):
            if room_id == "a-room":
                return defer.succeed(self.room_members)
            else:
                return defer.succeed([])
        room_member_handler.get_room_members = get_room_members

        def user_rooms_intersect(userlist):
            room_member_ids = map(lambda u: u.to_string(), self.room_members)

            shared = all(map(lambda i: i in room_member_ids, userlist))
            return defer.succeed(shared)
        self.store.user_rooms_intersect = user_rooms_intersect

        self.mock_start = Mock()
        self.mock_stop = Mock()

        self.handler.start_polling_presence = self.mock_start
        self.handler.stop_polling_presence = self.mock_stop

    @defer.inlineCallbacks
    def test_get_my_state(self):
        state = yield self.handler.get_state(
            target_user=self.u_apple, auth_user=self.u_apple
        )

        self.assertEquals(
            {"presence": ONLINE, "status_msg": "Online"},
            state
        )

    @defer.inlineCallbacks
    def test_get_allowed_state(self):
        yield self.store.allow_presence_visible(
            observed_localpart=self.u_apple.localpart,
            observer_userid=self.u_banana.to_string(),
        )

        state = yield self.handler.get_state(
            target_user=self.u_apple, auth_user=self.u_banana
        )

        self.assertEquals(
            {"presence": ONLINE, "status_msg": "Online"},
            state
        )

    @defer.inlineCallbacks
    def test_get_same_room_state(self):
        self.room_members = [self.u_apple, self.u_clementine]

        state = yield self.handler.get_state(
            target_user=self.u_apple, auth_user=self.u_clementine
        )

        self.assertEquals(
            {"presence": ONLINE, "status_msg": "Online"},
            state
        )

    @defer.inlineCallbacks
    def test_get_disallowed_state(self):
        self.room_members = []

        yield self.assertFailure(
            self.handler.get_state(
                target_user=self.u_apple, auth_user=self.u_clementine
            ),
            SynapseError
        )

    @defer.inlineCallbacks
    def test_set_my_state(self):
        yield self.handler.set_state(
                target_user=self.u_apple, auth_user=self.u_apple,
                state={"presence": UNAVAILABLE, "status_msg": "Away"})

        self.assertEquals(
            {"state": UNAVAILABLE,
             "status_msg": "Away",
             "mtime": 1000000},
            (yield self.store.get_presence_state(self.u_apple.localpart))
        )

        self.mock_start.assert_called_with(self.u_apple,
                state={
                    "presence": UNAVAILABLE,
                    "status_msg": "Away",
                    "last_active": 1000000, # MockClock
                })

        yield self.handler.set_state(
                target_user=self.u_apple, auth_user=self.u_apple,
                state={"presence": OFFLINE})

        self.mock_stop.assert_called_with(self.u_apple)


class PresenceInvitesTestCase(unittest.TestCase):
    """ Tests presence management. """

    @defer.inlineCallbacks
    def setUp(self):
        self.mock_http_client = Mock(spec=[])
        self.mock_http_client.put_json = DeferredMockCallable()

        self.mock_federation_resource = MockHttpResource()

        db_pool = SQLiteMemoryDbPool()
        yield db_pool.prepare()

        self.mock_config = NonCallableMock()
        self.mock_config.signing_key = [MockKey()]

        hs = HomeServer("test",
            clock=MockClock(),
            db_pool=db_pool,
            handlers=None,
            resource_for_client=Mock(),
            resource_for_federation=self.mock_federation_resource,
            http_client=self.mock_http_client,
            config=self.mock_config,
            keyring=Mock(),
        )
        hs.handlers = JustPresenceHandlers(hs)

        self.store = hs.get_datastore()

        # Some local users to test with
        self.u_apple = hs.parse_userid("@apple:test")
        self.u_banana = hs.parse_userid("@banana:test")
        yield self.store.create_presence(self.u_apple.localpart)
        yield self.store.create_presence(self.u_banana.localpart)

        # ID of a local user that does not exist
        self.u_durian = hs.parse_userid("@durian:test")

        # A remote user
        self.u_cabbage = hs.parse_userid("@cabbage:elsewhere")

        self.handler = hs.get_handlers().presence_handler

        self.mock_start = Mock()
        self.mock_stop = Mock()

        self.handler.start_polling_presence = self.mock_start
        self.handler.stop_polling_presence = self.mock_stop

    @defer.inlineCallbacks
    def test_invite_local(self):
        # TODO(paul): This test will likely break if/when real auth permissions
        # are added; for now the HS will always accept any invite

        yield self.handler.send_invite(
                observer_user=self.u_apple, observed_user=self.u_banana)

        self.assertEquals(
            [{"observed_user_id": "@banana:test", "accepted": 1}],
            (yield self.store.get_presence_list(self.u_apple.localpart))
        )
        self.assertTrue(
            (yield self.store.is_presence_visible(
                observed_localpart=self.u_banana.localpart,
                observer_userid=self.u_apple.to_string(),
            ))
        )

        self.mock_start.assert_called_with(
                self.u_apple, target_user=self.u_banana)

    @defer.inlineCallbacks
    def test_invite_local_nonexistant(self):
        yield self.handler.send_invite(
                observer_user=self.u_apple, observed_user=self.u_durian)

        self.assertEquals(
            [],
            (yield self.store.get_presence_list(self.u_apple.localpart))
        )

    @defer.inlineCallbacks
    def test_invite_remote(self):
        put_json = self.mock_http_client.put_json
        put_json.expect_call_and_return(
            call("elsewhere",
                path="/_matrix/federation/v1/send/1000000/",
                data=_expect_edu("elsewhere", "m.presence_invite",
                    content={
                        "observer_user": "@apple:test",
                        "observed_user": "@cabbage:elsewhere",
                    }
                ),
                json_data_callback=ANY,
            ),
            defer.succeed((200, "OK"))
        )

        yield self.handler.send_invite(
                observer_user=self.u_apple, observed_user=self.u_cabbage)

        self.assertEquals(
            [{"observed_user_id": "@cabbage:elsewhere", "accepted": 0}],
            (yield self.store.get_presence_list(self.u_apple.localpart))
        )

        yield put_json.await_calls()

    @defer.inlineCallbacks
    def test_accept_remote(self):
        # TODO(paul): This test will likely break if/when real auth permissions
        # are added; for now the HS will always accept any invite
        put_json = self.mock_http_client.put_json
        put_json.expect_call_and_return(
            call("elsewhere",
                path="/_matrix/federation/v1/send/1000000/",
                data=_expect_edu("elsewhere", "m.presence_accept",
                    content={
                        "observer_user": "@cabbage:elsewhere",
                        "observed_user": "@apple:test",
                    }
                ),
                json_data_callback=ANY,
            ),
            defer.succeed((200, "OK"))
        )

        yield self.mock_federation_resource.trigger("PUT",
            "/_matrix/federation/v1/send/1000000/",
            _make_edu_json("elsewhere", "m.presence_invite",
                content={
                    "observer_user": "@cabbage:elsewhere",
                    "observed_user": "@apple:test",
                }
            )
        )

        self.assertTrue(
            (yield self.store.is_presence_visible(
                observed_localpart=self.u_apple.localpart,
                observer_userid=self.u_cabbage.to_string(),
            ))
        )

        yield put_json.await_calls()

    @defer.inlineCallbacks
    def test_invited_remote_nonexistant(self):
        put_json = self.mock_http_client.put_json
        put_json.expect_call_and_return(
            call("elsewhere",
                path="/_matrix/federation/v1/send/1000000/",
                data=_expect_edu("elsewhere", "m.presence_deny",
                    content={
                        "observer_user": "@cabbage:elsewhere",
                        "observed_user": "@durian:test",
                    }
                ),
                json_data_callback=ANY,
            ),
            defer.succeed((200, "OK"))
        )

        yield self.mock_federation_resource.trigger("PUT",
            "/_matrix/federation/v1/send/1000000/",
            _make_edu_json("elsewhere", "m.presence_invite",
                content={
                    "observer_user": "@cabbage:elsewhere",
                    "observed_user": "@durian:test",
                }
            )
        )

        yield put_json.await_calls()

    @defer.inlineCallbacks
    def test_accepted_remote(self):
        yield self.store.add_presence_list_pending(
            observer_localpart=self.u_apple.localpart,
            observed_userid=self.u_cabbage.to_string(),
        )

        yield self.mock_federation_resource.trigger("PUT",
            "/_matrix/federation/v1/send/1000000/",
            _make_edu_json("elsewhere", "m.presence_accept",
                content={
                    "observer_user": "@apple:test",
                    "observed_user": "@cabbage:elsewhere",
                }
            )
        )

        self.assertEquals(
            [{"observed_user_id": "@cabbage:elsewhere", "accepted": 1}],
            (yield self.store.get_presence_list(self.u_apple.localpart))
        )

        self.mock_start.assert_called_with(
                self.u_apple, target_user=self.u_cabbage)

    @defer.inlineCallbacks
    def test_denied_remote(self):
        yield self.store.add_presence_list_pending(
            observer_localpart=self.u_apple.localpart,
            observed_userid="@eggplant:elsewhere",
        )

        yield self.mock_federation_resource.trigger("PUT",
            "/_matrix/federation/v1/send/1000000/",
            _make_edu_json("elsewhere", "m.presence_deny",
                content={
                    "observer_user": "@apple:test",
                    "observed_user": "@eggplant:elsewhere",
                }
            )
        )

        self.assertEquals(
            [],
            (yield self.store.get_presence_list(self.u_apple.localpart))
        )

    @defer.inlineCallbacks
    def test_drop_local(self):
        yield self.store.add_presence_list_pending(
            observer_localpart=self.u_apple.localpart,
            observed_userid=self.u_banana.to_string(),
        )
        yield self.store.set_presence_list_accepted(
            observer_localpart=self.u_apple.localpart,
            observed_userid=self.u_banana.to_string(),
        )

        yield self.handler.drop(
            observer_user=self.u_apple,
            observed_user=self.u_banana,
        )

        self.assertEquals(
            [],
            (yield self.store.get_presence_list(self.u_apple.localpart))
        )

        self.mock_stop.assert_called_with(
                self.u_apple, target_user=self.u_banana)

    @defer.inlineCallbacks
    def test_drop_remote(self):
        yield self.store.add_presence_list_pending(
            observer_localpart=self.u_apple.localpart,
            observed_userid=self.u_cabbage.to_string(),
        )
        yield self.store.set_presence_list_accepted(
            observer_localpart=self.u_apple.localpart,
            observed_userid=self.u_cabbage.to_string(),
        )

        yield self.handler.drop(
            observer_user=self.u_apple,
            observed_user=self.u_cabbage,
        )

        self.assertEquals(
            [],
            (yield self.store.get_presence_list(self.u_apple.localpart))
        )

    @defer.inlineCallbacks
    def test_get_presence_list(self):
        yield self.store.add_presence_list_pending(
            observer_localpart=self.u_apple.localpart,
            observed_userid=self.u_banana.to_string(),
        )
        yield self.store.set_presence_list_accepted(
            observer_localpart=self.u_apple.localpart,
            observed_userid=self.u_banana.to_string(),
        )

        presence = yield self.handler.get_presence_list(
                observer_user=self.u_apple)

        self.assertEquals([
            {"observed_user": self.u_banana,
             "presence": OFFLINE,
             "accepted": 1},
        ], presence)


class PresencePushTestCase(unittest.TestCase):
    """ Tests steady-state presence status updates.

    They assert that presence state update messages are pushed around the place
    when users change state, presuming that the watches are all established.

    These tests are MASSIVELY fragile currently as they poke internals of the
    presence handler; namely the _local_pushmap and _remote_recvmap.
    BE WARNED...
    """
    def setUp(self):
        self.clock = MockClock()

        self.mock_http_client = Mock(spec=[])
        self.mock_http_client.put_json = DeferredMockCallable()

        self.mock_federation_resource = MockHttpResource()

        self.mock_config = NonCallableMock()
        self.mock_config.signing_key = [MockKey()]

        hs = HomeServer("test",
                clock=self.clock,
                db_pool=None,
                datastore=Mock(spec=[
                    "set_presence_state",
                    "get_joined_hosts_for_room",

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
        hs.handlers = JustPresenceHandlers(hs)

        self.datastore = hs.get_datastore()

        def get_received_txn_response(*args):
            return defer.succeed(None)
        self.datastore.get_received_txn_response = get_received_txn_response

        self.handler = hs.get_handlers().presence_handler
        self.event_source = hs.get_event_sources().sources["presence"]

        # Mock the RoomMemberHandler
        hs.handlers.room_member_handler = Mock(spec=[
            "get_rooms_for_user",
            "get_room_members",
        ])
        self.room_member_handler = hs.handlers.room_member_handler

        self.room_members = []

        def get_rooms_for_user(user):
            if user in self.room_members:
                return defer.succeed(["a-room"])
            else:
                return defer.succeed([])
        self.room_member_handler.get_rooms_for_user = get_rooms_for_user

        def get_room_members(room_id):
            if room_id == "a-room":
                return defer.succeed(self.room_members)
            else:
                return defer.succeed([])
        self.room_member_handler.get_room_members = get_room_members

        def get_room_hosts(room_id):
            if room_id == "a-room":
                hosts = set([u.domain for u in self.room_members])
                return defer.succeed(hosts)
            else:
                return defer.succeed([])
        self.datastore.get_joined_hosts_for_room = get_room_hosts

        def user_rooms_intersect(userlist):
            room_member_ids = map(lambda u: u.to_string(), self.room_members)

            shared = all(map(lambda i: i in room_member_ids, userlist))
            return defer.succeed(shared)
        self.datastore.user_rooms_intersect = user_rooms_intersect

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

        def get_presence_list(user_localpart, accepted=None):
            if user_localpart == "apple":
                return defer.succeed([
                    {"observed_user_id": "@banana:test"},
                    {"observed_user_id": "@clementine:test"},
                ])
            else:
                return defer.succeed([])
        self.datastore.get_presence_list = get_presence_list

        def is_presence_visible(observer_userid, observed_localpart):
            if (observed_localpart == "clementine" and
                observer_userid == "@banana:test"):
                return False
            return False
        self.datastore.is_presence_visible = is_presence_visible

        self.distributor = hs.get_distributor()
        self.distributor.declare("user_joined_room")

        # Some local users to test with
        self.u_apple = hs.parse_userid("@apple:test")
        self.u_banana = hs.parse_userid("@banana:test")
        self.u_clementine = hs.parse_userid("@clementine:test")
        self.u_durian = hs.parse_userid("@durian:test")
        self.u_elderberry = hs.parse_userid("@elderberry:test")

        # Remote user
        self.u_onion = hs.parse_userid("@onion:farm")
        self.u_potato = hs.parse_userid("@potato:remote")

    @defer.inlineCallbacks
    def test_push_local(self):
        self.room_members = [self.u_apple, self.u_elderberry]

        self.datastore.set_presence_state.return_value = defer.succeed(
            {"state": ONLINE}
        )

        # TODO(paul): Gut-wrenching
        self.handler._user_cachemap[self.u_apple] = UserPresenceCache()
        self.handler._user_cachemap[self.u_apple].update(
            {"presence": OFFLINE}, serial=0
        )
        apple_set = self.handler._local_pushmap.setdefault("apple", set())
        apple_set.add(self.u_banana)
        apple_set.add(self.u_clementine)

        self.assertEquals(self.event_source.get_current_key(), 0)

        yield self.handler.set_state(self.u_apple, self.u_apple,
            {"presence": ONLINE}
        )

        # Apple sees self-reflection
        (events, _) = yield self.event_source.get_new_events_for_user(
            self.u_apple, 0, None
        )

        self.assertEquals(self.event_source.get_current_key(), 1)
        self.assertEquals(events,
            [
                {"type": "m.presence",
                 "content": {
                    "user_id": "@apple:test",
                    "presence": ONLINE,
                    "last_active_ago": 0,
                }},
            ],
            msg="Presence event should be visible to self-reflection"
        )

        config = SourcePaginationConfig(from_key=1, to_key=0)
        (chunk, _) = yield self.event_source.get_pagination_rows(
            self.u_apple, config, None
        )
        self.assertEquals(chunk,
            [
                {"type": "m.presence",
                 "content": {
                     "user_id": "@apple:test",
                     "presence": ONLINE,
                     "last_active_ago": 0,
                }},
            ]
        )

        # Banana sees it because of presence subscription
        (events, _) = yield self.event_source.get_new_events_for_user(
            self.u_banana, 0, None
        )

        self.assertEquals(self.event_source.get_current_key(), 1)
        self.assertEquals(events,
            [
                {"type": "m.presence",
                 "content": {
                    "user_id": "@apple:test",
                    "presence": ONLINE,
                    "last_active_ago": 0,
                }},
            ],
            msg="Presence event should be visible to explicit subscribers"
        )

        # Elderberry sees it because of same room
        (events, _) = yield self.event_source.get_new_events_for_user(
            self.u_elderberry, 0, None
        )

        self.assertEquals(self.event_source.get_current_key(), 1)
        self.assertEquals(events,
            [
                {"type": "m.presence",
                 "content": {
                    "user_id": "@apple:test",
                    "presence": ONLINE,
                    "last_active_ago": 0,
                }},
            ],
            msg="Presence event should be visible to other room members"
        )

        # Durian is not in the room, should not see this event
        (events, _) = yield self.event_source.get_new_events_for_user(
            self.u_durian, 0, None
        )

        self.assertEquals(self.event_source.get_current_key(), 1)
        self.assertEquals(events, [],
            msg="Presence event should not be visible to others"
        )

        presence = yield self.handler.get_presence_list(
                observer_user=self.u_apple, accepted=True)

        self.assertEquals(
            [
                {"observed_user": self.u_banana, 
                 "presence": OFFLINE},
                {"observed_user": self.u_clementine,
                 "presence": OFFLINE},
            ],
            presence
        )

        # TODO(paul): Gut-wrenching
        banana_set = self.handler._local_pushmap.setdefault("banana", set())
        banana_set.add(self.u_apple)

        yield self.handler.set_state(self.u_banana, self.u_banana,
            {"presence": ONLINE}
        )

        self.clock.advance_time(2)

        presence = yield self.handler.get_presence_list(
                observer_user=self.u_apple, accepted=True)

        self.assertEquals([
                {"observed_user": self.u_banana,
                 "presence": ONLINE,
                 "last_active_ago": 2000},
                {"observed_user": self.u_clementine,
                 "presence": OFFLINE},
        ], presence)

        (events, _) = yield self.event_source.get_new_events_for_user(
            self.u_apple, 1, None
        )

        self.assertEquals(self.event_source.get_current_key(), 2)
        self.assertEquals(events,
            [
                {"type": "m.presence",
                 "content": {
                     "user_id": "@banana:test",
                     "presence": ONLINE,
                     "last_active_ago": 2000
                }},
            ]
        )

    @defer.inlineCallbacks
    def test_push_remote(self):
        put_json = self.mock_http_client.put_json
        put_json.expect_call_and_return(
            call("farm",
                path=ANY,  # Can't guarantee which txn ID will be which
                data=_expect_edu("farm", "m.presence",
                    content={
                        "push": [
                            {"user_id": "@apple:test",
                             "presence": u"online",
                             "last_active_ago": 0},
                        ],
                    }
                ),
                json_data_callback=ANY,
            ),
            defer.succeed((200, "OK"))
        )
        put_json.expect_call_and_return(
            call("remote",
                path=ANY,  # Can't guarantee which txn ID will be which
                data=_expect_edu("remote", "m.presence",
                    content={
                        "push": [
                            {"user_id": "@apple:test",
                             "presence": u"online",
                             "last_active_ago": 0},
                        ],
                    }
                ),
                json_data_callback=ANY,
            ),
            defer.succeed((200, "OK"))
        )

        self.room_members = [self.u_apple, self.u_onion]

        self.datastore.set_presence_state.return_value = defer.succeed(
            {"state": ONLINE}
        )

        # TODO(paul): Gut-wrenching
        self.handler._user_cachemap[self.u_apple] = UserPresenceCache()
        self.handler._user_cachemap[self.u_apple].update(
            {"presence": OFFLINE}, serial=0
        )
        apple_set = self.handler._remote_sendmap.setdefault("apple", set())
        apple_set.add(self.u_potato.domain)

        yield self.handler.set_state(self.u_apple, self.u_apple,
            {"presence": ONLINE}
        )

        yield put_json.await_calls()

    @defer.inlineCallbacks
    def test_recv_remote(self):
        # TODO(paul): Gut-wrenching
        potato_set = self.handler._remote_recvmap.setdefault(self.u_potato,
                set())
        potato_set.add(self.u_apple)

        self.room_members = [self.u_banana, self.u_potato]

        self.assertEquals(self.event_source.get_current_key(), 0)

        yield self.mock_federation_resource.trigger("PUT",
            "/_matrix/federation/v1/send/1000000/",
            _make_edu_json("elsewhere", "m.presence",
                content={
                    "push": [
                        {"user_id": "@potato:remote",
                         "presence": "online",
                         "last_active_ago": 1000},
                    ],
                }
            )
        )

        (events, _) = yield self.event_source.get_new_events_for_user(
            self.u_apple, 0, None
        )

        self.assertEquals(self.event_source.get_current_key(), 1)
        self.assertEquals(events,
            [
                {"type": "m.presence",
                 "content": {
                     "user_id": "@potato:remote",
                     "presence": ONLINE,
                     "last_active_ago": 1000,
                }}
            ]
        )

        self.clock.advance_time(2)

        state = yield self.handler.get_state(self.u_potato, self.u_apple)

        self.assertEquals(
            {"presence": ONLINE, "last_active_ago": 3000},
            state
        )

    @defer.inlineCallbacks
    def test_join_room_local(self):
        self.room_members = [self.u_apple, self.u_banana]

        self.assertEquals(self.event_source.get_current_key(), 0)

        # TODO(paul): Gut-wrenching
        self.handler._user_cachemap[self.u_clementine] = UserPresenceCache()
        self.handler._user_cachemap[self.u_clementine].update(
            {
                "presence": PresenceState.ONLINE,
                "last_active": self.clock.time_msec(),
            }, self.u_clementine
        )

        yield self.distributor.fire("user_joined_room", self.u_clementine,
            "a-room"
        )

        self.room_members.append(self.u_clementine)

        (events, _) = yield self.event_source.get_new_events_for_user(
            self.u_apple, 0, None
        )

        self.assertEquals(self.event_source.get_current_key(), 1)
        self.assertEquals(events,
            [
                {"type": "m.presence",
                 "content": {
                     "user_id": "@clementine:test",
                     "presence": ONLINE,
                     "last_active_ago": 0,
                }}
            ]
        )

    @defer.inlineCallbacks
    def test_join_room_remote(self):
        ## Sending local user state to a newly-joined remote user
        put_json = self.mock_http_client.put_json
        put_json.expect_call_and_return(
            call("remote",
                path=ANY,  # Can't guarantee which txn ID will be which
                data=_expect_edu("remote", "m.presence",
                    content={
                        "push": [
                            {"user_id": "@apple:test",
                             "presence": "online"},
                        ],
                    }
                ),
                json_data_callback=ANY,
            ),
            defer.succeed((200, "OK"))
        )
        put_json.expect_call_and_return(
            call("remote",
                path=ANY,  # Can't guarantee which txn ID will be which
                data=_expect_edu("remote", "m.presence",
                    content={
                        "push": [
                            {"user_id": "@banana:test",
                             "presence": "offline"},
                        ],
                    }
                ),
                json_data_callback=ANY,
            ),
            defer.succeed((200, "OK"))
        )

        # TODO(paul): Gut-wrenching
        self.handler._user_cachemap[self.u_apple] = UserPresenceCache()
        self.handler._user_cachemap[self.u_apple].update(
                {"presence": PresenceState.ONLINE}, self.u_apple)
        self.room_members = [self.u_apple, self.u_banana]

        yield self.distributor.fire("user_joined_room", self.u_potato,
            "a-room"
        )

        yield put_json.await_calls()

        ## Sending newly-joined local user state to remote users

        put_json.expect_call_and_return(
            call("remote",
                path="/_matrix/federation/v1/send/1000002/",
                data=_expect_edu("remote", "m.presence",
                    content={
                        "push": [
                            {"user_id": "@clementine:test",
                             "presence": "online"},
                        ],
                    }
                ),
                json_data_callback=ANY,
            ),
            defer.succeed((200, "OK"))
        )

        self.handler._user_cachemap[self.u_clementine] = UserPresenceCache()
        self.handler._user_cachemap[self.u_clementine].update(
                {"presence": ONLINE}, self.u_clementine)
        self.room_members.append(self.u_potato)

        yield self.distributor.fire("user_joined_room", self.u_clementine,
            "a-room"
        )

        put_json.await_calls()


class PresencePollingTestCase(unittest.TestCase):
    """ Tests presence status polling. """

    # For this test, we have three local users; apple is watching and is
    # watched by the other two, but the others don't watch each other.
    # Additionally clementine is watching a remote user.
    PRESENCE_LIST = {
            'apple': [ "@banana:test", "@clementine:test" ],
            'banana': [ "@apple:test" ],
            'clementine': [ "@apple:test", "@potato:remote" ],
            'fig': [ "@potato:remote" ],
    }


    def setUp(self):
        self.mock_http_client = Mock(spec=[])
        self.mock_http_client.put_json = DeferredMockCallable()

        self.mock_federation_resource = MockHttpResource()

        self.mock_config = NonCallableMock()
        self.mock_config.signing_key = [MockKey()]

        hs = HomeServer("test",
                clock=MockClock(),
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
        hs.handlers = JustPresenceHandlers(hs)

        self.datastore = hs.get_datastore()

        def get_received_txn_response(*args):
            return defer.succeed(None)
        self.datastore.get_received_txn_response = get_received_txn_response

        self.mock_update_client = Mock()

        def update(*args,**kwargs):
            # print "mock_update_client: Args=%s, kwargs=%s" %(args, kwargs,)
            return defer.succeed(None)

        self.mock_update_client.side_effect = update

        self.handler = hs.get_handlers().presence_handler
        self.handler.push_update_to_clients = self.mock_update_client

        hs.handlers.room_member_handler = Mock(spec=[
            "get_rooms_for_user",
        ])
        # For this test no users are ever in rooms
        def get_rooms_for_user(user):
            return defer.succeed([])
        hs.handlers.room_member_handler.get_rooms_for_user = get_rooms_for_user

        # Mocked database state
        # Local users always start offline
        self.current_user_state = {
            "apple": OFFLINE,
            "banana": OFFLINE,
            "clementine": OFFLINE,
            "fig": OFFLINE,
        }

        def get_presence_state(user_localpart):
            return defer.succeed(
                    {"state": self.current_user_state[user_localpart],
                     "status_msg": None,
                     "mtime": 123456000}
            )
        self.datastore.get_presence_state = get_presence_state

        def set_presence_state(user_localpart, new_state):
            was = self.current_user_state[user_localpart]
            self.current_user_state[user_localpart] = new_state["state"]
            return defer.succeed({"state": was})
        self.datastore.set_presence_state = set_presence_state

        def get_presence_list(user_localpart, accepted):
            return defer.succeed([
                {"observed_user_id": u} for u in
                self.PRESENCE_LIST[user_localpart]])
        self.datastore.get_presence_list = get_presence_list

        def is_presence_visible(observed_localpart, observer_userid):
            return True
        self.datastore.is_presence_visible = is_presence_visible

        # Local users
        self.u_apple = hs.parse_userid("@apple:test")
        self.u_banana = hs.parse_userid("@banana:test")
        self.u_clementine = hs.parse_userid("@clementine:test")
        self.u_fig = hs.parse_userid("@fig:test")

        # Remote users
        self.u_potato = hs.parse_userid("@potato:remote")

    @defer.inlineCallbacks
    def test_push_local(self):
        # apple goes online
        yield self.handler.set_state(
            target_user=self.u_apple, auth_user=self.u_apple,
            state={"presence": ONLINE}
        )

        # apple should see both banana and clementine currently offline
        self.mock_update_client.assert_has_calls([
                call(users_to_push=[self.u_apple],
                    observed_user=self.u_banana,
                    statuscache=ANY),
                call(users_to_push=[self.u_apple],
                    observed_user=self.u_clementine,
                    statuscache=ANY),
        ], any_order=True)

        # Gut-wrenching tests
        self.assertTrue("banana" in self.handler._local_pushmap)
        self.assertTrue(self.u_apple in self.handler._local_pushmap["banana"])
        self.assertTrue("clementine" in self.handler._local_pushmap)
        self.assertTrue(self.u_apple in self.handler._local_pushmap["clementine"])

        self.mock_update_client.reset_mock()

        # banana goes online
        yield self.handler.set_state(
            target_user=self.u_banana, auth_user=self.u_banana,
            state={"presence": ONLINE}
        )

        # apple and banana should now both see each other online
        self.mock_update_client.assert_has_calls([
                call(users_to_push=set([self.u_apple]),
                    observed_user=self.u_banana,
                    room_ids=[],
                    statuscache=ANY),
                call(users_to_push=[self.u_banana],
                    observed_user=self.u_apple,
                    statuscache=ANY),
        ], any_order=True)

        self.assertTrue("apple" in self.handler._local_pushmap)
        self.assertTrue(self.u_banana in self.handler._local_pushmap["apple"])

        self.mock_update_client.reset_mock()

        # apple goes offline
        yield self.handler.set_state(
            target_user=self.u_apple, auth_user=self.u_apple,
            state={"presence": OFFLINE}
        )

        # banana should now be told apple is offline
        self.mock_update_client.assert_has_calls([
                call(users_to_push=set([self.u_banana, self.u_apple]),
                    observed_user=self.u_apple,
                    room_ids=[],
                    statuscache=ANY),
        ], any_order=True)

        self.assertFalse("banana" in self.handler._local_pushmap)
        self.assertFalse("clementine" in self.handler._local_pushmap)

    @defer.inlineCallbacks
    def test_remote_poll_send(self):
        put_json = self.mock_http_client.put_json
        put_json.expect_call_and_return(
            call("remote",
                path=ANY,
                data=_expect_edu("remote", "m.presence",
                    content={
                        "poll": [ "@potato:remote" ],
                    },
                ),
                json_data_callback=ANY,
            ),
            defer.succeed((200, "OK"))
        )

        put_json.expect_call_and_return(
            call("remote",
                path=ANY,
                data=_expect_edu("remote", "m.presence",
                    content={
                        "push": [ {
                            "user_id": "@clementine:test",
                            "presence": OFFLINE,
                        }],
                    },
                ),
                json_data_callback=ANY,
            ),
            defer.succeed((200, "OK"))
        )

        # clementine goes online
        yield self.handler.set_state(
            target_user=self.u_clementine, auth_user=self.u_clementine,
            state={"presence": ONLINE}
        )

        yield put_json.await_calls()

        # Gut-wrenching tests
        self.assertTrue(self.u_potato in self.handler._remote_recvmap,
            msg="expected potato to be in _remote_recvmap"
        )
        self.assertTrue(self.u_clementine in
                self.handler._remote_recvmap[self.u_potato])


        put_json.expect_call_and_return(
            call("remote",
                path=ANY,
                data=_expect_edu("remote", "m.presence",
                    content={
                        "push": [ {
                            "user_id": "@fig:test",
                            "presence": OFFLINE,
                        }],
                    },
                ),
                json_data_callback=ANY,
            ),
            defer.succeed((200, "OK"))
        )

        # fig goes online; shouldn't send a second poll
        yield self.handler.set_state(
            target_user=self.u_fig, auth_user=self.u_fig,
            state={"presence": ONLINE}
        )

        # reactor.iterate(delay=0)

        yield put_json.await_calls()

        # fig goes offline
        yield self.handler.set_state(
            target_user=self.u_fig, auth_user=self.u_fig,
            state={"presence": OFFLINE}
        )

        reactor.iterate(delay=0)

        put_json.assert_had_no_calls()

        put_json.expect_call_and_return(
            call("remote",
                path=ANY,
                data=_expect_edu("remote", "m.presence",
                    content={
                        "unpoll": [ "@potato:remote" ],
                    },
                ),
                json_data_callback=ANY,
            ),
            defer.succeed((200, "OK"))
        )

        # clementine goes offline
        yield self.handler.set_state(
            target_user=self.u_clementine, auth_user=self.u_clementine,
            state={"presence": OFFLINE}
        )

        yield put_json.await_calls()

        self.assertFalse(self.u_potato in self.handler._remote_recvmap,
            msg="expected potato not to be in _remote_recvmap"
        )

    @defer.inlineCallbacks
    def test_remote_poll_receive(self):
        put_json = self.mock_http_client.put_json
        put_json.expect_call_and_return(
            call("remote",
                path="/_matrix/federation/v1/send/1000000/",
                data=_expect_edu("remote", "m.presence",
                    content={
                        "push": [
                            {"user_id": "@banana:test",
                             "presence": "offline",
                             "status_msg": None},
                        ],
                    },
                ),
                json_data_callback=ANY,
            ),
            defer.succeed((200, "OK"))
        )

        yield self.mock_federation_resource.trigger("PUT",
            "/_matrix/federation/v1/send/1000000/",
            _make_edu_json("remote", "m.presence",
                content={
                    "poll": [ "@banana:test" ],
                },
            )
        )

        yield put_json.await_calls()

        # Gut-wrenching tests
        self.assertTrue(self.u_banana in self.handler._remote_sendmap)

        yield self.mock_federation_resource.trigger("PUT",
            "/_matrix/federation/v1/send/1000001/",
            _make_edu_json("remote", "m.presence",
                content={
                    "unpoll": [ "@banana:test" ],
                }
            )
        )

        # Gut-wrenching tests
        self.assertFalse(self.u_banana in self.handler._remote_sendmap)
