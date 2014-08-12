# -*- coding: utf-8 -*-

from twisted.internet import defer
from twisted.trial import unittest

from synapse.api.events.room import (
    InviteJoinEvent, RoomMemberEvent, RoomConfigEvent
)
from synapse.api.constants import Membership
from synapse.handlers.room import RoomMemberHandler, RoomCreationHandler
from synapse.handlers.profile import ProfileHandler
from synapse.server import HomeServer

from mock import Mock, NonCallableMock

import logging

logging.getLogger().addHandler(logging.NullHandler())


class RoomMemberHandlerTestCase(unittest.TestCase):

    def setUp(self):
        self.hostname = "red"
        hs = HomeServer(
            self.hostname,
            db_pool=None,
            datastore=NonCallableMock(spec_set=[
                "store_room_member",
                "get_joined_hosts_for_room",
                "get_room_member",
                "get_room",
                "store_room",
            ]),
            http_server=NonCallableMock(),
            http_client=NonCallableMock(spec_set=[]),
            notifier=NonCallableMock(spec_set=["on_new_room_event"]),
            handlers=NonCallableMock(spec_set=[
                "room_member_handler",
                "profile_handler",
            ]),
            auth=NonCallableMock(spec_set=["check"]),
            federation=NonCallableMock(spec_set=[
                "handle_new_event",
                "get_state_for_room",
            ]),
            state_handler=NonCallableMock(spec_set=["handle_new_event"]),
        )

        self.datastore = hs.get_datastore()
        self.handlers = hs.get_handlers()
        self.notifier = hs.get_notifier()
        self.federation = hs.get_federation()
        self.state_handler = hs.get_state_handler()
        self.distributor = hs.get_distributor()
        self.hs = hs

        self.handlers.room_member_handler = RoomMemberHandler(self.hs)
        self.handlers.profile_handler = ProfileHandler(self.hs)
        self.room_member_handler = self.handlers.room_member_handler

    @defer.inlineCallbacks
    def test_invite(self):
        room_id = "!foo:red"
        user_id = "@bob:red"
        target_user_id = "@red:blue"
        content = {"membership": Membership.INVITE}

        event = self.hs.get_event_factory().create_event(
            etype=RoomMemberEvent.TYPE,
            user_id=user_id,
            target_user_id=target_user_id,
            room_id=room_id,
            membership=Membership.INVITE,
            content=content,
        )

        joined = ["red", "green"]

        self.state_handler.handle_new_event.return_value = defer.succeed(True)
        self.datastore.get_joined_hosts_for_room.return_value = (
            defer.succeed(joined)
        )

        store_id = "store_id_fooo"
        self.datastore.store_room_member.return_value = defer.succeed(store_id)

        # Actual invocation
        yield self.room_member_handler.change_membership(event)

        self.state_handler.handle_new_event.assert_called_once_with(event)
        self.federation.handle_new_event.assert_called_once_with(event)

        self.assertEquals(
            set(["blue", "red", "green"]),
            set(event.destinations)
        )

        self.datastore.store_room_member.assert_called_once_with(
            user_id=target_user_id,
            sender=user_id,
            room_id=room_id,
            content=content,
            membership=Membership.INVITE,
        )
        self.notifier.on_new_room_event.assert_called_once_with(
                event, store_id)

        self.assertFalse(self.datastore.get_room.called)
        self.assertFalse(self.datastore.store_room.called)
        self.assertFalse(self.federation.get_state_for_room.called)

    @defer.inlineCallbacks
    def test_simple_join(self):
        room_id = "!foo:red"
        user_id = "@bob:red"
        user = self.hs.parse_userid(user_id)
        target_user_id = "@bob:red"
        content = {"membership": Membership.JOIN}

        event = self.hs.get_event_factory().create_event(
            etype=RoomMemberEvent.TYPE,
            user_id=user_id,
            target_user_id=target_user_id,
            room_id=room_id,
            membership=Membership.JOIN,
            content=content,
        )

        joined = ["red", "green"]

        self.state_handler.handle_new_event.return_value = defer.succeed(True)
        self.datastore.get_joined_hosts_for_room.return_value = (
            defer.succeed(joined)
        )

        store_id = "store_id_fooo"
        self.datastore.store_room_member.return_value = defer.succeed(store_id)
        self.datastore.get_room.return_value = defer.succeed(1)  # Not None.

        prev_state = NonCallableMock()
        prev_state.membership = Membership.INVITE
        prev_state.sender = "@foo:red"
        self.datastore.get_room_member.return_value = defer.succeed(prev_state)

        join_signal_observer = Mock()
        self.distributor.observe("user_joined_room", join_signal_observer)

        # Actual invocation
        yield self.room_member_handler.change_membership(event)

        self.state_handler.handle_new_event.assert_called_once_with(event)
        self.federation.handle_new_event.assert_called_once_with(event)

        self.assertEquals(
            set(["red", "green"]),
            set(event.destinations)
        )

        self.datastore.store_room_member.assert_called_once_with(
            user_id=target_user_id,
            sender=user_id,
            room_id=room_id,
            content=content,
            membership=Membership.JOIN,
        )
        self.notifier.on_new_room_event.assert_called_once_with(
                event, store_id)

        join_signal_observer.assert_called_with(
                user=user, room_id=room_id)

    @defer.inlineCallbacks
    def STALE_test_invite_join(self):
        room_id = "foo"
        user_id = "@bob:red"
        target_user_id = "@bob:red"
        content = {"membership": Membership.JOIN}

        event = self.hs.get_event_factory().create_event(
            etype=RoomMemberEvent.TYPE,
            user_id=user_id,
            target_user_id=target_user_id,
            room_id=room_id,
            membership=Membership.JOIN,
            content=content,
        )

        joined = ["red", "blue", "green"]

        self.state_handler.handle_new_event.return_value = defer.succeed(True)
        self.datastore.get_joined_hosts_for_room.return_value = (
            defer.succeed(joined)
        )

        store_id = "store_id_fooo"
        self.datastore.store_room_member.return_value = defer.succeed(store_id)
        self.datastore.get_room.return_value = defer.succeed(None)

        prev_state = NonCallableMock(name="prev_state")
        prev_state.membership = Membership.INVITE
        prev_state.sender = "@foo:blue"
        self.datastore.get_room_member.return_value = defer.succeed(prev_state)

        # Actual invocation
        yield self.room_member_handler.change_membership(event)

        self.datastore.get_room_member.assert_called_once_with(
            target_user_id, room_id
        )

        self.assertTrue(self.federation.handle_new_event.called)
        args = self.federation.handle_new_event.call_args[0]
        invite_join_event = args[0]

        self.assertTrue(InviteJoinEvent.TYPE, invite_join_event.TYPE)
        self.assertTrue("blue", invite_join_event.target_host)
        self.assertTrue(room_id, invite_join_event.room_id)
        self.assertTrue(user_id, invite_join_event.user_id)
        self.assertFalse(hasattr(invite_join_event, "state_key"))

        self.assertEquals(
            set(["blue"]),
            set(invite_join_event.destinations)
        )

        self.federation.get_state_for_room.assert_called_once_with(
            "blue", room_id
        )

        self.assertFalse(self.datastore.store_room_member.called)

        self.assertFalse(self.notifier.on_new_room_event.called)
        self.assertFalse(self.state_handler.handle_new_event.called)

    @defer.inlineCallbacks
    def STALE_test_invite_join_public(self):
        room_id = "#foo:blue"
        user_id = "@bob:red"
        target_user_id = "@bob:red"
        content = {"membership": Membership.JOIN}

        event = self.hs.get_event_factory().create_event(
            etype=RoomMemberEvent.TYPE,
            user_id=user_id,
            target_user_id=target_user_id,
            room_id=room_id,
            membership=Membership.JOIN,
            content=content,
        )

        joined = ["red", "blue", "green"]

        self.state_handler.handle_new_event.return_value = defer.succeed(True)
        self.datastore.get_joined_hosts_for_room.return_value = (
            defer.succeed(joined)
        )

        store_id = "store_id_fooo"
        self.datastore.store_room_member.return_value = defer.succeed(store_id)
        self.datastore.get_room.return_value = defer.succeed(None)

        prev_state = NonCallableMock(name="prev_state")
        prev_state.membership = Membership.INVITE
        prev_state.sender = "@foo:blue"
        self.datastore.get_room_member.return_value = defer.succeed(prev_state)

        # Actual invocation
        yield self.room_member_handler.change_membership(event)

        self.assertTrue(self.federation.handle_new_event.called)
        args = self.federation.handle_new_event.call_args[0]
        invite_join_event = args[0]

        self.assertTrue(InviteJoinEvent.TYPE, invite_join_event.TYPE)
        self.assertTrue("blue", invite_join_event.target_host)
        self.assertTrue("foo", invite_join_event.room_id)
        self.assertTrue(user_id, invite_join_event.user_id)
        self.assertFalse(hasattr(invite_join_event, "state_key"))

        self.assertEquals(
            set(["blue"]),
            set(invite_join_event.destinations)
        )

        self.federation.get_state_for_room.assert_called_once_with(
            "blue", "foo"
        )

        self.assertFalse(self.datastore.store_room_member.called)

        self.assertFalse(self.notifier.on_new_room_event.called)
        self.assertFalse(self.state_handler.handle_new_event.called)


class RoomCreationTest(unittest.TestCase):

    def setUp(self):
        self.hostname = "red"
        hs = HomeServer(
            self.hostname,
            db_pool=None,
            datastore=NonCallableMock(spec_set=[
                "store_room",
            ]),
            http_server=NonCallableMock(),
            http_client=NonCallableMock(spec_set=[]),
            notifier=NonCallableMock(spec_set=["on_new_room_event"]),
            handlers=NonCallableMock(spec_set=[
                "room_creation_handler",
                "room_member_handler",
            ]),
            auth=NonCallableMock(spec_set=["check"]),
            federation=NonCallableMock(spec_set=[
                "handle_new_event",
            ]),
            state_handler=NonCallableMock(spec_set=["handle_new_event"]),
        )

        self.datastore = hs.get_datastore()
        self.handlers = hs.get_handlers()
        self.notifier = hs.get_notifier()
        self.federation = hs.get_federation()
        self.state_handler = hs.get_state_handler()
        self.hs = hs

        self.handlers.room_creation_handler = RoomCreationHandler(self.hs)
        self.room_creation_handler = self.handlers.room_creation_handler

        self.handlers.room_member_handler = NonCallableMock(spec_set=[
            "change_membership"
        ])
        self.room_member_handler = self.handlers.room_member_handler

    @defer.inlineCallbacks
    def test_room_creation(self):
        user_id = "@foo:red"
        room_id = "!bobs_room:red"
        config = {"visibility": "private"}

        yield self.room_creation_handler.create_room(
            user_id=user_id,
            room_id=room_id,
            config=config,
        )

        self.assertTrue(self.room_member_handler.change_membership.called)
        join_event = self.room_member_handler.change_membership.call_args[0][0]

        self.assertEquals(RoomMemberEvent.TYPE, join_event.type)
        self.assertEquals(room_id, join_event.room_id)
        self.assertEquals(user_id, join_event.user_id)
        self.assertEquals(user_id, join_event.target_user_id)

        self.assertTrue(self.state_handler.handle_new_event.called)

        self.assertTrue(self.federation.handle_new_event.called)
        config_event = self.federation.handle_new_event.call_args[0][0]

        self.assertEquals(RoomConfigEvent.TYPE, config_event.type)
        self.assertEquals(room_id, config_event.room_id)
        self.assertEquals(user_id, config_event.user_id)
        self.assertEquals(config, config_event.content)
