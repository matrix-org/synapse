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

from mock import Mock, call, ANY, NonCallableMock
import json

from tests.utils import (
    MockHttpResource, MockClock, DeferredMockCallable, setup_test_homeserver
)

from synapse.api.constants import PresenceState
from synapse.api.errors import SynapseError
from synapse.handlers.presence import PresenceHandler, UserPresenceCache
from synapse.streams.config import SourcePaginationConfig
from synapse.storage.transactions import DestinationsTable
from synapse.types import UserID

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


class PresenceTestCase(unittest.TestCase):
    @defer.inlineCallbacks
    def setUp(self):
        self.clock = MockClock()

        self.mock_federation_resource = MockHttpResource()

        self.mock_http_client = Mock(spec=[])
        self.mock_http_client.put_json = DeferredMockCallable()

        hs_kwargs = {}
        if hasattr(self, "make_datastore_mock"):
            hs_kwargs["datastore"] = self.make_datastore_mock()

        hs = yield setup_test_homeserver(
            clock=self.clock,
            handlers=None,
            resource_for_federation=self.mock_federation_resource,
            http_client=self.mock_http_client,
            keyring=Mock(),
            **hs_kwargs
        )
        hs.handlers = JustPresenceHandlers(hs)

        self.datastore = hs.get_datastore()

        self.setUp_roommemberhandler_mocks(hs.handlers)

        self.handler = hs.get_handlers().presence_handler
        self.event_source = hs.get_event_sources().sources["presence"]

        self.distributor = hs.get_distributor()
        self.distributor.declare("user_joined_room")

        yield self.setUp_users(hs)

    def setUp_roommemberhandler_mocks(self, handlers):
        self.room_id = "a-room"
        self.room_members = []

        room_member_handler = handlers.room_member_handler = Mock(spec=[
            "get_rooms_for_user",
            "get_room_members",
            "fetch_room_distributions_into",
        ])
        self.room_member_handler = room_member_handler

        def get_rooms_for_user(user):
            if user in self.room_members:
                return defer.succeed([self.room_id])
            else:
                return defer.succeed([])
        room_member_handler.get_rooms_for_user = get_rooms_for_user

        def get_room_members(room_id):
            if room_id == self.room_id:
                return defer.succeed(self.room_members)
            else:
                return defer.succeed([])
        room_member_handler.get_room_members = get_room_members

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
        room_member_handler.fetch_room_distributions_into = (
                fetch_room_distributions_into)

        self.setUp_datastore_room_mocks(self.datastore)

    def setUp_datastore_room_mocks(self, datastore):
        def get_room_hosts(room_id):
            if room_id == self.room_id:
                hosts = set([u.domain for u in self.room_members])
                return defer.succeed(hosts)
            else:
                return defer.succeed([])
        datastore.get_joined_hosts_for_room = get_room_hosts

        def user_rooms_intersect(userlist):
            room_member_ids = map(lambda u: u.to_string(), self.room_members)

            shared = all(map(lambda i: i in room_member_ids, userlist))
            return defer.succeed(shared)
        datastore.user_rooms_intersect = user_rooms_intersect

    @defer.inlineCallbacks
    def setUp_users(self, hs):
        # Some local users to test with
        self.u_apple = UserID.from_string("@apple:test")
        self.u_banana = UserID.from_string("@banana:test")
        self.u_clementine = UserID.from_string("@clementine:test")

        for u in self.u_apple, self.u_banana, self.u_clementine:
            yield self.datastore.create_presence(u.localpart)

        yield self.datastore.set_presence_state(
            self.u_apple.localpart, {"state": ONLINE, "status_msg": "Online"}
        )

        # ID of a local user that does not exist
        self.u_durian = UserID.from_string("@durian:test")

        # A remote user
        self.u_cabbage = UserID.from_string("@cabbage:elsewhere")


class MockedDatastorePresenceTestCase(PresenceTestCase):
    def make_datastore_mock(self):
        datastore = Mock(spec=[
            # Bits that Federation needs
            "prep_send_transaction",
            "delivered_txn",
            "get_received_txn_response",
            "set_received_txn_response",
            "get_destination_retry_timings",
        ])

        self.setUp_datastore_federation_mocks(datastore)
        self.setUp_datastore_presence_mocks(datastore)

        return datastore

    def setUp_datastore_federation_mocks(self, datastore):
        datastore.get_destination_retry_timings.return_value = (
            defer.succeed(DestinationsTable.EntryType("", 0, 0))
        )

        def get_received_txn_response(*args):
            return defer.succeed(None)
        datastore.get_received_txn_response = get_received_txn_response

    def setUp_datastore_presence_mocks(self, datastore):
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
        datastore.get_presence_state = get_presence_state

        def set_presence_state(user_localpart, new_state):
            was = self.current_user_state[user_localpart]
            self.current_user_state[user_localpart] = new_state["state"]
            return defer.succeed({"state": was})
        datastore.set_presence_state = set_presence_state

        def get_presence_list(user_localpart, accepted):
            if not user_localpart in self.PRESENCE_LIST:
                return defer.succeed([])
            return defer.succeed([
                {"observed_user_id": u} for u in
                self.PRESENCE_LIST[user_localpart]])
        datastore.get_presence_list = get_presence_list

        def is_presence_visible(observed_localpart, observer_userid):
            return True
        datastore.is_presence_visible = is_presence_visible

    @defer.inlineCallbacks
    def setUp_users(self, hs):
        # Some local users to test with
        self.u_apple = UserID.from_string("@apple:test")
        self.u_banana = UserID.from_string("@banana:test")
        self.u_clementine = UserID.from_string("@clementine:test")
        self.u_durian = UserID.from_string("@durian:test")
        self.u_elderberry = UserID.from_string("@elderberry:test")
        self.u_fig = UserID.from_string("@fig:test")

        # Remote user
        self.u_onion = UserID.from_string("@onion:farm")
        self.u_potato = UserID.from_string("@potato:remote")

        yield


class PresenceStateTestCase(PresenceTestCase):
    """ Tests presence management. """
    @defer.inlineCallbacks
    def setUp(self):
        yield super(PresenceStateTestCase, self).setUp()

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
        yield self.datastore.allow_presence_visible(
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
            (yield self.datastore.get_presence_state(self.u_apple.localpart))
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


class PresenceInvitesTestCase(PresenceTestCase):
    """ Tests presence management. """
    @defer.inlineCallbacks
    def setUp(self):
        yield super(PresenceInvitesTestCase, self).setUp()

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
            (yield self.datastore.get_presence_list(self.u_apple.localpart))
        )
        self.assertTrue(
            (yield self.datastore.is_presence_visible(
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
            (yield self.datastore.get_presence_list(self.u_apple.localpart))
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
            (yield self.datastore.get_presence_list(self.u_apple.localpart))
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
            (yield self.datastore.is_presence_visible(
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
        yield self.datastore.add_presence_list_pending(
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
            (yield self.datastore.get_presence_list(self.u_apple.localpart))
        )

        self.mock_start.assert_called_with(
                self.u_apple, target_user=self.u_cabbage)

    @defer.inlineCallbacks
    def test_denied_remote(self):
        yield self.datastore.add_presence_list_pending(
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
            (yield self.datastore.get_presence_list(self.u_apple.localpart))
        )

    @defer.inlineCallbacks
    def test_drop_local(self):
        yield self.datastore.add_presence_list_pending(
            observer_localpart=self.u_apple.localpart,
            observed_userid=self.u_banana.to_string(),
        )
        yield self.datastore.set_presence_list_accepted(
            observer_localpart=self.u_apple.localpart,
            observed_userid=self.u_banana.to_string(),
        )

        yield self.handler.drop(
            observer_user=self.u_apple,
            observed_user=self.u_banana,
        )

        self.assertEquals(
            [],
            (yield self.datastore.get_presence_list(self.u_apple.localpart))
        )

        self.mock_stop.assert_called_with(
                self.u_apple, target_user=self.u_banana)

    @defer.inlineCallbacks
    def test_drop_remote(self):
        yield self.datastore.add_presence_list_pending(
            observer_localpart=self.u_apple.localpart,
            observed_userid=self.u_cabbage.to_string(),
        )
        yield self.datastore.set_presence_list_accepted(
            observer_localpart=self.u_apple.localpart,
            observed_userid=self.u_cabbage.to_string(),
        )

        yield self.handler.drop(
            observer_user=self.u_apple,
            observed_user=self.u_cabbage,
        )

        self.assertEquals(
            [],
            (yield self.datastore.get_presence_list(self.u_apple.localpart))
        )

    @defer.inlineCallbacks
    def test_get_presence_list(self):
        yield self.datastore.add_presence_list_pending(
            observer_localpart=self.u_apple.localpart,
            observed_userid=self.u_banana.to_string(),
        )
        yield self.datastore.set_presence_list_accepted(
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


class PresencePushTestCase(MockedDatastorePresenceTestCase):
    """ Tests steady-state presence status updates.

    They assert that presence state update messages are pushed around the place
    when users change state, presuming that the watches are all established.

    These tests are MASSIVELY fragile currently as they poke internals of the
    presence handler; namely the _local_pushmap and _remote_recvmap.
    BE WARNED...
    """
    PRESENCE_LIST = {
            'apple': [ "@banana:test", "@clementine:test" ],
    }

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
            self.room_id
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
            self.room_id
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
            self.room_id
        )

        put_json.await_calls()


class PresencePollingTestCase(MockedDatastorePresenceTestCase):
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

    @defer.inlineCallbacks
    def setUp(self):
        yield super(PresencePollingTestCase, self).setUp()

        self.mock_update_client = Mock()

        def update(*args,**kwargs):
            return defer.succeed(None)
        self.mock_update_client.side_effect = update

        self.handler.push_update_to_clients = self.mock_update_client

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
