# -*- coding: utf-8 -*-

from twisted.trial import unittest
from twisted.internet import defer

from mock import Mock, call, ANY
import logging

from synapse.server import HomeServer
from synapse.api.constants import PresenceState
from synapse.api.errors import SynapseError
from synapse.handlers.presence import PresenceHandler, UserPresenceCache


OFFLINE = PresenceState.OFFLINE
BUSY = PresenceState.BUSY
ONLINE = PresenceState.ONLINE


logging.getLogger().addHandler(logging.NullHandler())


class MockReplication(object):
    def __init__(self):
        self.edu_handlers = {}

    def register_edu_handler(self, edu_type, handler):
        self.edu_handlers[edu_type] = handler

    def received_edu(self, origin, edu_type, content):
        self.edu_handlers[edu_type](origin, content)


class JustPresenceHandlers(object):
    def __init__(self, hs):
        self.presence_handler = PresenceHandler(hs)


class PresenceStateTestCase(unittest.TestCase):
    """ Tests presence management. """

    def setUp(self):
        hs = HomeServer("test",
                db_pool=None,
                datastore=Mock(spec=[
                    "get_presence_state",
                    "set_presence_state",
                    "add_presence_list_pending",
                    "set_presence_list_accepted",
                ]),
                handlers=None,
                http_server=Mock(),
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

        # Some local users to test with
        self.u_apple = hs.parse_userid("@apple:test")
        self.u_banana = hs.parse_userid("@banana:test")
        self.u_clementine = hs.parse_userid("@clementine:test")

        self.handler = hs.get_handlers().presence_handler

        hs.handlers.room_member_handler = Mock(spec=[
            "get_rooms_for_user",
        ])
        hs.handlers.room_member_handler.get_rooms_for_user = (
                lambda u: defer.succeed([]))

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
    def test_get_disallowed_state(self):
        mocked_get = self.datastore.get_presence_state
        mocked_get.return_value = defer.succeed(
            {"state": ONLINE, "status_msg": "Online"}
        )

        yield self.assertFailure(
            self.handler.get_state(
                target_user=self.u_apple, auth_user=self.u_clementine
            ),
            SynapseError
        )

    @defer.inlineCallbacks
    def test_set_my_state(self):
        mocked_set = self.datastore.set_presence_state
        mocked_set.return_value = defer.succeed({"state": OFFLINE})

        yield self.handler.set_state(
                target_user=self.u_apple, auth_user=self.u_apple,
                state={"state": BUSY, "status_msg": "Away"})

        mocked_set.assert_called_with("apple",
                {"state": 1, "status_msg": "Away"})
        self.mock_start.assert_called_with(self.u_apple,
                state={"state": 1, "status_msg": "Away"})

        yield self.handler.set_state(
                target_user=self.u_apple, auth_user=self.u_apple,
                state={"state": OFFLINE})

        self.mock_stop.assert_called_with(self.u_apple)


class PresenceInvitesTestCase(unittest.TestCase):
    """ Tests presence management. """

    def setUp(self):
        self.replication = MockReplication()
        self.replication.send_edu = Mock()

        hs = HomeServer("test",
                db_pool=None,
                datastore=Mock(spec=[
                    "has_presence_state",
                    "allow_presence_visible",
                    "add_presence_list_pending",
                    "set_presence_list_accepted",
                    "get_presence_list",
                    "del_presence_list",
                ]),
                handlers=None,
                http_server=Mock(),
                http_client=None,
                replication_layer=self.replication
            )
        hs.handlers = JustPresenceHandlers(hs)

        self.datastore = hs.get_datastore()

        def has_presence_state(user_localpart):
            return defer.succeed(
                user_localpart in ("apple", "banana"))
        self.datastore.has_presence_state = has_presence_state

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
        self.replication.send_edu.return_value = defer.succeed((200, "OK"))

        yield self.handler.send_invite(
                observer_user=self.u_apple, observed_user=self.u_cabbage)

        self.datastore.add_presence_list_pending.assert_called_with(
                "apple", "@cabbage:elsewhere")

        self.replication.send_edu.assert_called_with(
                destination="elsewhere",
                edu_type="m.presence_invite",
                content={
                    "observer_user": "@apple:test",
                    "observed_user": "@cabbage:elsewhere",
                }
        )

    @defer.inlineCallbacks
    def test_accept_remote(self):
        # TODO(paul): This test will likely break if/when real auth permissions
        # are added; for now the HS will always accept any invite
        self.replication.send_edu.return_value = defer.succeed((200, "OK"))

        yield self.replication.received_edu(
                "elsewhere", "m.presence_invite", {
                    "observer_user": "@cabbage:elsewhere",
                    "observed_user": "@apple:test",
                }
        )

        self.datastore.allow_presence_visible.assert_called_with(
                "apple", "@cabbage:elsewhere")

        self.replication.send_edu.assert_called_with(
                destination="elsewhere",
                edu_type="m.presence_accept",
                content={
                    "observer_user": "@cabbage:elsewhere",
                    "observed_user": "@apple:test",
                }
        )

    @defer.inlineCallbacks
    def test_invited_remote_nonexistant(self):
        self.replication.send_edu.return_value = defer.succeed((200, "OK"))

        yield self.replication.received_edu(
                "elsewhere", "m.presence_invite", {
                    "observer_user": "@cabbage:elsewhere",
                    "observed_user": "@durian:test",
                }
        )

        self.replication.send_edu.assert_called_with(
                destination="elsewhere",
                edu_type="m.presence_deny",
                content={
                    "observer_user": "@cabbage:elsewhere",
                    "observed_user": "@durian:test",
                }
        )

    @defer.inlineCallbacks
    def test_accepted_remote(self):
        yield self.replication.received_edu(
                "elsewhere", "m.presence_accept", {
                    "observer_user": "@apple:test",
                    "observed_user": "@cabbage:elsewhere",
                }
        )

        self.datastore.set_presence_list_accepted.assert_called_with(
                "apple", "@cabbage:elsewhere")

        self.mock_start.assert_called_with(
                self.u_apple, target_user=self.u_cabbage)

    @defer.inlineCallbacks
    def test_denied_remote(self):
        yield self.replication.received_edu(
                "elsewhere", "m.presence_deny", {
                    "observer_user": "@apple:test",
                    "observed_user": "@eggplant:elsewhere",
                }
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
        self.replication = MockReplication()
        self.replication.send_edu = Mock()
        self.replication.send_edu.return_value = defer.succeed((200, "OK"))

        hs = HomeServer("test",
                db_pool=None,
                datastore=Mock(spec=[
                    "set_presence_state",
                ]),
                handlers=None,
                http_server=Mock(),
                http_client=None,
                replication_layer=self.replication,
            )
        hs.handlers = JustPresenceHandlers(hs)

        self.mock_update_client = Mock()
        self.mock_update_client.return_value = defer.succeed(None)

        self.datastore = hs.get_datastore()
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
                call(observer_user=self.u_apple,
                    observed_user=self.u_apple,
                    statuscache=ANY), # self-reflection
                call(observer_user=self.u_banana,
                    observed_user=self.u_apple,
                    statuscache=ANY),
                call(observer_user=self.u_clementine,
                    observed_user=self.u_apple,
                    statuscache=ANY),
                call(observer_user=self.u_elderberry,
                    observed_user=self.u_apple,
                    statuscache=ANY),
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

        presence = yield self.handler.get_presence_list(
                observer_user=self.u_apple, accepted=True)

        self.assertEquals([
                {"observed_user": self.u_banana, "state": ONLINE},
                {"observed_user": self.u_clementine, "state": OFFLINE}],
            presence)

        self.mock_update_client.assert_has_calls([
                call(observer_user=self.u_banana,
                    observed_user=self.u_banana,
                    statuscache=ANY), # self-reflection
        ]) # and no others...

    @defer.inlineCallbacks
    def test_push_remote(self):
        self.room_members = [self.u_apple, self.u_onion]

        self.datastore.set_presence_state.return_value = defer.succeed(
                {"state": ONLINE})

        # TODO(paul): Gut-wrenching
        self.handler._user_cachemap[self.u_apple] = UserPresenceCache()
        apple_set = self.handler._remote_sendmap.setdefault("apple", set())
        apple_set.add(self.u_potato.domain)

        yield self.handler.set_state(self.u_apple, self.u_apple,
                {"state": ONLINE})

        self.replication.send_edu.assert_has_calls([
                call(
                    destination="remote",
                    edu_type="m.presence",
                    content={
                        "push": [
                            {"user_id": "@apple:test",
                            "state": 2},
                        ],
                    }),
                call(
                    destination="farm",
                    edu_type="m.presence",
                    content={
                        "push": [
                            {"user_id": "@apple:test",
                             "state": 2},
                        ],
                    })
        ], any_order=True)

    @defer.inlineCallbacks
    def test_recv_remote(self):
        # TODO(paul): Gut-wrenching
        potato_set = self.handler._remote_recvmap.setdefault(self.u_potato,
                set())
        potato_set.add(self.u_apple)

        self.room_members = [self.u_banana, self.u_potato]

        yield self.replication.received_edu(
                "remote", "m.presence", {
                    "push": [
                        {"user_id": "@potato:remote",
                         "state": 2},
                    ],
                }
        )

        self.mock_update_client.assert_has_calls([
                call(observer_user=self.u_apple,
                    observed_user=self.u_potato,
                    statuscache=ANY),
                call(observer_user=self.u_banana,
                    observed_user=self.u_potato,
                    statuscache=ANY),
        ], any_order=True)

        state = yield self.handler.get_state(self.u_potato, self.u_apple)

        self.assertEquals({"state": ONLINE}, state)

    @defer.inlineCallbacks
    def test_join_room_local(self):
        self.room_members = [self.u_apple, self.u_banana]

        yield self.distributor.fire("user_joined_room", self.u_elderberry,
            "a-room"
        )

        self.mock_update_client.assert_has_calls([
            # Apple and Elderberry see each other
            call(observer_user=self.u_apple,
                observed_user=self.u_elderberry,
                statuscache=ANY),
            call(observer_user=self.u_elderberry,
                observed_user=self.u_apple,
                statuscache=ANY),
            # Banana and Elderberry see each other
            call(observer_user=self.u_banana,
                observed_user=self.u_elderberry,
                statuscache=ANY),
            call(observer_user=self.u_elderberry,
                observed_user=self.u_banana,
                statuscache=ANY),
        ], any_order=True)

    @defer.inlineCallbacks
    def test_join_room_remote(self):
        ## Sending local user state to a newly-joined remote user

        # TODO(paul): Gut-wrenching
        self.handler._user_cachemap[self.u_apple] = UserPresenceCache()
        self.handler._user_cachemap[self.u_apple].update(
                {"state": PresenceState.ONLINE}, self.u_apple)
        self.room_members = [self.u_apple, self.u_banana]

        yield self.distributor.fire("user_joined_room", self.u_potato,
            "a-room"
        )

        self.replication.send_edu.assert_has_calls([
                call(
                    destination="remote",
                    edu_type="m.presence",
                    content={
                        "push": [
                            {"user_id": "@apple:test",
                            "state": 2},
                        ],
                    }),
                call(
                    destination="remote",
                    edu_type="m.presence",
                    content={
                        "push": [
                            {"user_id": "@banana:test",
                            "state": 0},
                        ],
                    }),
        ], any_order=True)

        self.replication.send_edu.reset_mock()

        ## Sending newly-joined local user state to remote users

        self.handler._user_cachemap[self.u_clementine] = UserPresenceCache()
        self.handler._user_cachemap[self.u_clementine].update(
                {"state": PresenceState.ONLINE}, self.u_clementine)
        self.room_members.append(self.u_potato)

        yield self.distributor.fire("user_joined_room", self.u_clementine,
            "a-room"
        )

        self.replication.send_edu.assert_has_calls(
                call(
                    destination="remote",
                    edu_type="m.presence",
                    content={
                        "push": [
                            {"user_id": "@clementine:test",
                            "state": 2},
                        ],
                    }),
        )


class PresencePollingTestCase(unittest.TestCase):
    """ Tests presence status polling. """

    # For this test, we have three local users; apple is watching and is
    # watched by the other two, but the others don't watch each other.
    # Additionally clementine is watching a remote user.
    PRESENCE_LIST = {
            'apple': [ "@banana:test", "@clementine:test" ],
            'banana': [ "@apple:test" ],
            'clementine': [ "@apple:test", "@potato:remote" ],
    }


    def setUp(self):
        self.replication = MockReplication()
        self.replication.send_edu = Mock()

        hs = HomeServer("test",
                db_pool=None,
                datastore=Mock(spec=[]),
                handlers=None,
                http_server=Mock(),
                http_client=None,
                replication_layer=self.replication,
            )
        hs.handlers = JustPresenceHandlers(hs)

        self.datastore = hs.get_datastore()

        self.mock_update_client = Mock()
        self.mock_update_client.return_value = defer.succeed(None)

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

        # Remote users
        self.u_potato = hs.parse_userid("@potato:remote")

    @defer.inlineCallbacks
    def test_push_local(self):
        # apple goes online
        yield self.handler.set_state(
                target_user=self.u_apple, auth_user=self.u_apple,
                state={"state": ONLINE})

        # apple should see both banana and clementine currently offline
        self.mock_update_client.assert_has_calls([
                call(observer_user=self.u_apple,
                    observed_user=self.u_banana,
                    statuscache=ANY),
                call(observer_user=self.u_apple,
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
                call(observer_user=self.u_apple,
                    observed_user=self.u_banana,
                    statuscache=ANY),
                call(observer_user=self.u_banana,
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
                call(observer_user=self.u_banana,
                    observed_user=self.u_apple,
                    statuscache=ANY),
        ], any_order=True)

        self.assertFalse("banana" in self.handler._local_pushmap)
        self.assertFalse("clementine" in self.handler._local_pushmap)

    @defer.inlineCallbacks
    def test_remote_poll_send(self):
        # clementine goes online
        yield self.handler.set_state(
                target_user=self.u_clementine, auth_user=self.u_clementine,
                state={"state": ONLINE})

        self.replication.send_edu.assert_called_with(
                destination="remote",
                edu_type="m.presence",
                content={
                    "poll": [ "@potato:remote" ],
                },
        )

        # Gut-wrenching tests
        self.assertTrue(self.u_potato in self.handler._remote_recvmap)
        self.assertTrue(self.u_clementine in
                self.handler._remote_recvmap[self.u_potato])

        self.replication.send_edu.reset_mock()

        # clementine goes offline
        yield self.handler.set_state(
                target_user=self.u_clementine, auth_user=self.u_clementine,
                state={"state": OFFLINE})

        self.replication.send_edu.assert_called_with(
                destination="remote",
                edu_type="m.presence",
                content={
                    "unpoll": [ "@potato:remote" ],
                },
        )

        self.assertFalse(self.u_potato in self.handler._remote_recvmap)

    @defer.inlineCallbacks
    def test_remote_poll_receive(self):
        yield self.replication.received_edu(
                "remote", "m.presence", {
                    "poll": [ "@banana:test" ],
                }
        )

        # Gut-wrenching tests
        self.assertTrue(self.u_banana in self.handler._remote_sendmap)

        self.replication.send_edu.assert_called_with(
                destination="remote",
                edu_type="m.presence",
                content={
                    "push": [
                        {"user_id": "@banana:test",
                         "state": 0,
                         "status_msg": None},
                    ],
                },
        )

        yield self.replication.received_edu(
                "remote", "m.presence", {
                    "unpoll": [ "@banana:test" ],
                }
        )

        # Gut-wrenching tests
        self.assertFalse(self.u_banana in self.handler._remote_sendmap)
