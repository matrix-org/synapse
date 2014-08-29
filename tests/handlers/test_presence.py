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


from twisted.trial import unittest
from twisted.internet import defer, reactor

from mock import Mock, call, ANY
import logging
import json

from ..utils import MockHttpResource, MockClock, DeferredMockCallable

from synapse.server import HomeServer
from synapse.api.constants import PresenceState
from synapse.api.errors import SynapseError
from synapse.handlers.presence import PresenceHandler, UserPresenceCache


OFFLINE = PresenceState.OFFLINE
UNAVAILABLE = PresenceState.UNAVAILABLE
ONLINE = PresenceState.ONLINE


logging.getLogger().addHandler(logging.NullHandler())
#logging.getLogger().addHandler(logging.StreamHandler())
#logging.getLogger().setLevel(logging.DEBUG)


def _expect_edu(destination, edu_type, content, origin="test"):
    return {
        "origin": origin,
        "ts": 1000000,
        "pdus": [],
        "edus": [
            {
                "origin": origin,
                "destination": destination,
                "edu_type": edu_type,
                "content": content,
            }
        ],
    }

def _make_edu_json(origin, edu_type, content):
    return json.dumps(_expect_edu("test", edu_type, content, origin=origin))


class JustPresenceHandlers(object):
    def __init__(self, hs):
        self.presence_handler = PresenceHandler(hs)


class PresenceStateTestCase(unittest.TestCase):
    """ Tests presence management. """

    def setUp(self):
        hs = HomeServer("test",
                clock=MockClock(),
                db_pool=None,
                datastore=Mock(spec=[
                    "get_presence_state",
                    "set_presence_state",
                    "add_presence_list_pending",
                    "set_presence_list_accepted",
                ]),
                handlers=None,
                resource_for_federation=Mock(),
                http_client=None,
            )
        hs.handlers = JustPresenceHandlers(hs)

        self.datastore = hs.get_datastore()

        def is_presence_visible(observed_localpart, observer_userid):
            allow = (observed_localpart == "apple" and
                observer_userid == "@banana:test"
            )
            return defer.succeed(allow)
        self.datastore.is_presence_visible = is_presence_visible

        # Mock the RoomMemberHandler
        room_member_handler = Mock(spec=[])
        hs.handlers.room_member_handler = room_member_handler
        logging.getLogger().debug("Mocking room_member_handler=%r", room_member_handler)

        # Some local users to test with
        self.u_apple = hs.parse_userid("@apple:test")
        self.u_banana = hs.parse_userid("@banana:test")
        self.u_clementine = hs.parse_userid("@clementine:test")

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

        def do_users_share_a_room(userlist):
            shared = all(map(lambda u: u in self.room_members, userlist))
            return defer.succeed(shared)
        self.datastore.do_users_share_a_room = do_users_share_a_room

        self.mock_start = Mock()
        self.mock_stop = Mock()

        self.handler.start_polling_presence = self.mock_start
        self.handler.stop_polling_presence = self.mock_stop

    @defer.inlineCallbacks
    def test_get_my_state(self):
        mocked_get = self.datastore.get_presence_state
        mocked_get.return_value = defer.succeed(
            {"state": ONLINE, "status_msg": "Online"}
        )

        state = yield self.handler.get_state(
            target_user=self.u_apple, auth_user=self.u_apple
        )

        self.assertEquals({"state": ONLINE, "status_msg": "Online"},
            state
        )
        mocked_get.assert_called_with("apple")

    @defer.inlineCallbacks
    def test_get_allowed_state(self):
        mocked_get = self.datastore.get_presence_state
        mocked_get.return_value = defer.succeed(
            {"state": ONLINE, "status_msg": "Online"}
        )

        state = yield self.handler.get_state(
            target_user=self.u_apple, auth_user=self.u_banana
        )

        self.assertEquals({"state": ONLINE, "status_msg": "Online"},
            state
        )
        mocked_get.assert_called_with("apple")

    @defer.inlineCallbacks
    def test_get_same_room_state(self):
        mocked_get = self.datastore.get_presence_state
        mocked_get.return_value = defer.succeed(
            {"state": ONLINE, "status_msg": "Online"}
        )

        self.room_members = [self.u_apple, self.u_clementine]

        state = yield self.handler.get_state(
            target_user=self.u_apple, auth_user=self.u_clementine
        )

        self.assertEquals({"state": ONLINE, "status_msg": "Online"}, state)

    @defer.inlineCallbacks
    def test_get_disallowed_state(self):
        mocked_get = self.datastore.get_presence_state
        mocked_get.return_value = defer.succeed(
            {"state": ONLINE, "status_msg": "Online"}
        )

        self.room_members = []

        yield self.assertFailure(
            self.handler.get_state(
                target_user=self.u_apple, auth_user=self.u_clementine
            ),
            SynapseError
        )

    test_get_disallowed_state.skip = "Presence permissions are disabled"

    @defer.inlineCallbacks
    def test_set_my_state(self):
        mocked_set = self.datastore.set_presence_state
        mocked_set.return_value = defer.succeed({"state": OFFLINE})

        yield self.handler.set_state(
                target_user=self.u_apple, auth_user=self.u_apple,
                state={"state": UNAVAILABLE, "status_msg": "Away"})

        mocked_set.assert_called_with("apple",
                {"state": UNAVAILABLE, "status_msg": "Away"})
        self.mock_start.assert_called_with(self.u_apple,
                state={
                    "state": UNAVAILABLE,
                    "status_msg": "Away",
                    "mtime": 1000000, # MockClock
                })

        yield self.handler.set_state(
                target_user=self.u_apple, auth_user=self.u_apple,
                state={"state": OFFLINE})

        self.mock_stop.assert_called_with(self.u_apple)


class PresenceInvitesTestCase(unittest.TestCase):
    """ Tests presence management. """

    def setUp(self):
        self.mock_http_client = Mock(spec=[])
        self.mock_http_client.put_json = DeferredMockCallable()

        self.mock_federation_resource = MockHttpResource()

        hs = HomeServer("test",
                clock=MockClock(),
                db_pool=None,
                datastore=Mock(spec=[
                    "has_presence_state",
                    "allow_presence_visible",
                    "add_presence_list_pending",
                    "set_presence_list_accepted",
                    "get_presence_list",
                    "del_presence_list",

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
            )
        hs.handlers = JustPresenceHandlers(hs)

        self.datastore = hs.get_datastore()

        def has_presence_state(user_localpart):
            return defer.succeed(
                user_localpart in ("apple", "banana"))
        self.datastore.has_presence_state = has_presence_state

        def get_received_txn_response(*args):
            return defer.succeed(None)
        self.datastore.get_received_txn_response = get_received_txn_response

        # Some local users to test with
        self.u_apple = hs.parse_userid("@apple:test")
        self.u_banana = hs.parse_userid("@banana:test")
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

        self.datastore.add_presence_list_pending.assert_called_with(
                "apple", "@banana:test")
        self.datastore.allow_presence_visible.assert_called_with(
                "banana", "@apple:test")
        self.datastore.set_presence_list_accepted.assert_called_with(
                "apple", "@banana:test")

        self.mock_start.assert_called_with(
                self.u_apple, target_user=self.u_banana)

    @defer.inlineCallbacks
    def test_invite_local_nonexistant(self):
        yield self.handler.send_invite(
                observer_user=self.u_apple, observed_user=self.u_durian)

        self.datastore.add_presence_list_pending.assert_called_with(
                "apple", "@durian:test")
        self.datastore.del_presence_list.assert_called_with(
                "apple", "@durian:test")

    @defer.inlineCallbacks
    def test_invite_remote(self):
        put_json = self.mock_http_client.put_json
        put_json.expect_call_and_return(
            call("elsewhere",
                path="/matrix/federation/v1/send/1000000/",
                data=_expect_edu("elsewhere", "m.presence_invite",
                    content={
                        "observer_user": "@apple:test",
                        "observed_user": "@cabbage:elsewhere",
                    }
                )
            ),
            defer.succeed((200, "OK"))
        )

        yield self.handler.send_invite(
                observer_user=self.u_apple, observed_user=self.u_cabbage)

        self.datastore.add_presence_list_pending.assert_called_with(
                "apple", "@cabbage:elsewhere")

        yield put_json.await_calls()

    @defer.inlineCallbacks
    def test_accept_remote(self):
        # TODO(paul): This test will likely break if/when real auth permissions
        # are added; for now the HS will always accept any invite
        put_json = self.mock_http_client.put_json
        put_json.expect_call_and_return(
            call("elsewhere",
                path="/matrix/federation/v1/send/1000000/",
                data=_expect_edu("elsewhere", "m.presence_accept",
                    content={
                        "observer_user": "@cabbage:elsewhere",
                        "observed_user": "@apple:test",
                    }
                )
            ),
            defer.succeed((200, "OK"))
        )

        yield self.mock_federation_resource.trigger("PUT",
            "/matrix/federation/v1/send/1000000/",
            _make_edu_json("elsewhere", "m.presence_invite",
                content={
                    "observer_user": "@cabbage:elsewhere",
                    "observed_user": "@apple:test",
                }
            )
        )

        self.datastore.allow_presence_visible.assert_called_with(
                "apple", "@cabbage:elsewhere")

        yield put_json.await_calls()

    @defer.inlineCallbacks
    def test_invited_remote_nonexistant(self):
        put_json = self.mock_http_client.put_json
        put_json.expect_call_and_return(
            call("elsewhere",
                path="/matrix/federation/v1/send/1000000/",
                data=_expect_edu("elsewhere", "m.presence_deny",
                    content={
                        "observer_user": "@cabbage:elsewhere",
                        "observed_user": "@durian:test",
                    }
                )
            ),
            defer.succeed((200, "OK"))
        )

        yield self.mock_federation_resource.trigger("PUT",
            "/matrix/federation/v1/send/1000000/",
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
        yield self.mock_federation_resource.trigger("PUT",
            "/matrix/federation/v1/send/1000000/",
            _make_edu_json("elsewhere", "m.presence_accept",
                content={
                    "observer_user": "@apple:test",
                    "observed_user": "@cabbage:elsewhere",
                }
            )
        )

        self.datastore.set_presence_list_accepted.assert_called_with(
                "apple", "@cabbage:elsewhere")

        self.mock_start.assert_called_with(
                self.u_apple, target_user=self.u_cabbage)

    @defer.inlineCallbacks
    def test_denied_remote(self):
        yield self.mock_federation_resource.trigger("PUT",
            "/matrix/federation/v1/send/1000000/",
            _make_edu_json("elsewhere", "m.presence_deny",
                content={
                    "observer_user": "@apple:test",
                    "observed_user": "@eggplant:elsewhere",
                }
            )
        )

        self.datastore.del_presence_list.assert_called_with(
                "apple", "@eggplant:elsewhere")

    @defer.inlineCallbacks
    def test_drop_local(self):
        yield self.handler.drop(
                observer_user=self.u_apple, observed_user=self.u_banana)

        self.datastore.del_presence_list.assert_called_with(
                "apple", "@banana:test")

        self.mock_stop.assert_called_with(
                self.u_apple, target_user=self.u_banana)

    @defer.inlineCallbacks
    def test_drop_remote(self):
        yield self.handler.drop(
                observer_user=self.u_apple, observed_user=self.u_cabbage)

        self.datastore.del_presence_list.assert_called_with(
                "apple", "@cabbage:elsewhere")

    @defer.inlineCallbacks
    def test_get_presence_list(self):
        self.datastore.get_presence_list.return_value = defer.succeed(
                [{"observed_user_id": "@banana:test"}]
        )

        presence = yield self.handler.get_presence_list(
                observer_user=self.u_apple)

        self.assertEquals([{"observed_user": self.u_banana,
                            "state": OFFLINE}], presence)

        self.datastore.get_presence_list.assert_called_with("apple",
                accepted=None)


        self.datastore.get_presence_list.return_value = defer.succeed(
                [{"observed_user_id": "@banana:test"}]
        )

        presence = yield self.handler.get_presence_list(
                observer_user=self.u_apple, accepted=True)

        self.assertEquals([{"observed_user": self.u_banana,
                            "state": OFFLINE}], presence)

        self.datastore.get_presence_list.assert_called_with("apple",
                accepted=True)


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
            )
        hs.handlers = JustPresenceHandlers(hs)

        def update(*args,**kwargs):
            # print "mock_update_client: Args=%s, kwargs=%s" %(args, kwargs,)
            return defer.succeed(None)

        self.mock_update_client = Mock()
        self.mock_update_client.side_effect = update

        self.datastore = hs.get_datastore()

        def get_received_txn_response(*args):
            return defer.succeed(None)
        self.datastore.get_received_txn_response = get_received_txn_response

        self.handler = hs.get_handlers().presence_handler
        self.handler.push_update_to_clients = self.mock_update_client

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
        self.u_elderberry = hs.parse_userid("@elderberry:test")

        # Remote user
        self.u_onion = hs.parse_userid("@onion:farm")
        self.u_potato = hs.parse_userid("@potato:remote")

    @defer.inlineCallbacks
    def test_push_local(self):
        self.room_members = [self.u_apple, self.u_elderberry]

        self.datastore.set_presence_state.return_value = defer.succeed(
                {"state": ONLINE})

        # TODO(paul): Gut-wrenching
        self.handler._user_cachemap[self.u_apple] = UserPresenceCache()
        apple_set = self.handler._local_pushmap.setdefault("apple", set())
        apple_set.add(self.u_banana)
        apple_set.add(self.u_clementine)

        yield self.handler.set_state(self.u_apple, self.u_apple,
                {"state": ONLINE})

        self.mock_update_client.assert_has_calls([
                call(users_to_push=set([self.u_apple, self.u_banana, self.u_clementine]),
                    room_ids=["a-room"],
                    observed_user=self.u_apple,
                    statuscache=ANY), # self-reflection
        ], any_order=True)
        self.mock_update_client.reset_mock()

        presence = yield self.handler.get_presence_list(
                observer_user=self.u_apple, accepted=True)

        self.assertEquals([
                {"observed_user": self.u_banana, "state": OFFLINE},
                {"observed_user": self.u_clementine, "state": OFFLINE}],
            presence)

        yield self.handler.set_state(self.u_banana, self.u_banana,
                {"state": ONLINE})

        self.clock.advance_time(2)

        presence = yield self.handler.get_presence_list(
                observer_user=self.u_apple, accepted=True)

        self.assertEquals([
                {"observed_user": self.u_banana,
                 "state": ONLINE,
                 "mtime_age": 2000},
                {"observed_user": self.u_clementine,
                 "state": OFFLINE},
        ], presence)

        self.mock_update_client.assert_has_calls([
                call(users_to_push=set([self.u_banana]),
                    room_ids=[],
                    observed_user=self.u_banana,
                    statuscache=ANY), # self-reflection
        ]) # and no others...

    @defer.inlineCallbacks
    def test_push_remote(self):
        put_json = self.mock_http_client.put_json
#        put_json.expect_call_and_return(
#            call("remote",
#                path=ANY,  # Can't guarantee which txn ID will be which
#                data=_expect_edu("remote", "m.presence",
#                    content={
#                        "push": [
#                            {"user_id": "@apple:test",
#                             "state": "online",
#                             "mtime_age": 0},
#                        ],
#                    }
#                )
#            ),
#            defer.succeed((200, "OK"))
#        )
        put_json.expect_call_and_return(
            call("farm",
                path=ANY,  # Can't guarantee which txn ID will be which
                data=_expect_edu("farm", "m.presence",
                    content={
                        "push": [
                            {"user_id": "@apple:test",
                             "state": u"online",
                             "mtime_age": 0},
                        ],
                    }
                )
            ),
            defer.succeed((200, "OK"))
        )

        self.room_members = [self.u_apple, self.u_onion]

        self.datastore.set_presence_state.return_value = defer.succeed(
            {"state": ONLINE}
        )

        # TODO(paul): Gut-wrenching
        self.handler._user_cachemap[self.u_apple] = UserPresenceCache()
        apple_set = self.handler._remote_sendmap.setdefault("apple", set())
        apple_set.add(self.u_potato.domain)

        yield self.handler.set_state(self.u_apple, self.u_apple,
            {"state": ONLINE}
        )

        yield put_json.await_calls()

    @defer.inlineCallbacks
    def test_recv_remote(self):
        # TODO(paul): Gut-wrenching
        potato_set = self.handler._remote_recvmap.setdefault(self.u_potato,
                set())
        potato_set.add(self.u_apple)

        self.room_members = [self.u_banana, self.u_potato]

        yield self.mock_federation_resource.trigger("PUT",
            "/matrix/federation/v1/send/1000000/",
            _make_edu_json("elsewhere", "m.presence",
                content={
                    "push": [
                        {"user_id": "@potato:remote",
                         "state": "online",
                         "mtime_age": 1000},
                    ],
                }
            )
        )

        self.mock_update_client.assert_has_calls([
                call(users_to_push=set([self.u_apple]),
                    room_ids=["a-room"],
                    observed_user=self.u_potato,
                    statuscache=ANY),
        ], any_order=True)

        self.clock.advance_time(2)

        state = yield self.handler.get_state(self.u_potato, self.u_apple)

        self.assertEquals({"state": ONLINE, "mtime_age": 3000}, state)

    @defer.inlineCallbacks
    def test_join_room_local(self):
        self.room_members = [self.u_apple, self.u_banana]

        yield self.distributor.fire("user_joined_room", self.u_elderberry,
            "a-room"
        )

        self.mock_update_client.assert_has_calls([
            call(room_ids=["a-room"],
                observed_user=self.u_elderberry,
                users_to_push=set(),
                statuscache=ANY),
            call(users_to_push=set([self.u_elderberry]),
                observed_user=self.u_apple,
                room_ids=[],
                statuscache=ANY),
            call(users_to_push=set([self.u_elderberry]),
                observed_user=self.u_banana,
                room_ids=[],
                statuscache=ANY),
        ], any_order=True)

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
                            "state": "online"},
                        ],
                    }
                ),
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
                            "state": "offline"},
                        ],
                    }
                ),
            ),
            defer.succeed((200, "OK"))
        )

        # TODO(paul): Gut-wrenching
        self.handler._user_cachemap[self.u_apple] = UserPresenceCache()
        self.handler._user_cachemap[self.u_apple].update(
                {"state": PresenceState.ONLINE}, self.u_apple)
        self.room_members = [self.u_apple, self.u_banana]

        yield self.distributor.fire("user_joined_room", self.u_potato,
            "a-room"
        )

        yield put_json.await_calls()

        ## Sending newly-joined local user state to remote users

        put_json.expect_call_and_return(
            call("remote",
                path="/matrix/federation/v1/send/1000002/",
                data=_expect_edu("remote", "m.presence",
                    content={
                        "push": [
                            {"user_id": "@clementine:test",
                            "state": "online"},
                        ],
                    }
                ),
            ),
            defer.succeed((200, "OK"))
        )

        self.handler._user_cachemap[self.u_clementine] = UserPresenceCache()
        self.handler._user_cachemap[self.u_clementine].update(
                {"state": ONLINE}, self.u_clementine)
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
                     "status_msg": None}
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
            state={"state": ONLINE}
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
                state={"state": ONLINE})

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
                state={"state": OFFLINE})

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
            ),
            defer.succeed((200, "OK"))
        )

        put_json.expect_call_and_return(
            call("remote",
                path=ANY,
                data=_expect_edu("remote", "m.presence",
                    content={
                        "push": [ {"user_id": "@clementine:test" }],
                    },
                ),
            ),
            defer.succeed((200, "OK"))
        )

        # clementine goes online
        yield self.handler.set_state(
                target_user=self.u_clementine, auth_user=self.u_clementine,
                state={"state": ONLINE})

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
                        "push": [ {"user_id": "@fig:test" }],
                    },
                ),
            ),
            defer.succeed((200, "OK"))
        )

        # fig goes online; shouldn't send a second poll
        yield self.handler.set_state(
            target_user=self.u_fig, auth_user=self.u_fig,
            state={"state": ONLINE}
        )

        # reactor.iterate(delay=0)

        yield put_json.await_calls()

        # fig goes offline
        yield self.handler.set_state(
            target_user=self.u_fig, auth_user=self.u_fig,
            state={"state": OFFLINE}
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
            ),
            defer.succeed((200, "OK"))
        )

        # clementine goes offline
        yield self.handler.set_state(
                target_user=self.u_clementine, auth_user=self.u_clementine,
                state={"state": OFFLINE})

        yield put_json.await_calls()

        self.assertFalse(self.u_potato in self.handler._remote_recvmap,
            msg="expected potato not to be in _remote_recvmap"
        )

    @defer.inlineCallbacks
    def test_remote_poll_receive(self):
        put_json = self.mock_http_client.put_json
        put_json.expect_call_and_return(
            call("remote",
                path="/matrix/federation/v1/send/1000000/",
                data=_expect_edu("remote", "m.presence",
                    content={
                        "push": [
                            {"user_id": "@banana:test",
                             "state": "offline",
                             "status_msg": None},
                        ],
                    },
                ),
            ),
            defer.succeed((200, "OK"))
        )

        yield self.mock_federation_resource.trigger("PUT",
            "/matrix/federation/v1/send/1000000/",
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
            "/matrix/federation/v1/send/1000001/",
            _make_edu_json("remote", "m.presence",
                content={
                    "unpoll": [ "@banana:test" ],
                }
            )
        )

        # Gut-wrenching tests
        self.assertFalse(self.u_banana in self.handler._remote_sendmap)
