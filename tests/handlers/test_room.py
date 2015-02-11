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


from twisted.internet import defer
from .. import unittest

from synapse.api.constants import EventTypes, Membership
from synapse.handlers.room import RoomMemberHandler, RoomCreationHandler
from synapse.handlers.profile import ProfileHandler
from synapse.types import UserID
from ..utils import setup_test_homeserver

from mock import Mock, NonCallableMock


class RoomMemberHandlerTestCase(unittest.TestCase):

    @defer.inlineCallbacks
    def setUp(self):
        self.hostname = "red"
        hs = yield setup_test_homeserver(
            self.hostname,
            ratelimiter=NonCallableMock(spec_set=[
                "send_message",
            ]),
            datastore=NonCallableMock(spec_set=[
                "persist_event",
                "get_room_member",
                "get_room",
                "store_room",
                "get_latest_events_in_room",
            ]),
            resource_for_federation=NonCallableMock(),
            http_client=NonCallableMock(spec_set=[]),
            notifier=NonCallableMock(spec_set=["on_new_room_event"]),
            handlers=NonCallableMock(spec_set=[
                "room_member_handler",
                "profile_handler",
                "federation_handler",
            ]),
            auth=NonCallableMock(spec_set=[
                "check",
                "add_auth_events",
                "check_host_in_room",
            ]),
            state_handler=NonCallableMock(spec_set=[
                "compute_event_context",
                "get_current_state",
            ]),
        )

        self.federation = NonCallableMock(spec_set=[
            "handle_new_event",
            "send_invite",
            "get_state_for_room",
        ])

        self.datastore = hs.get_datastore()
        self.handlers = hs.get_handlers()
        self.notifier = hs.get_notifier()
        self.state_handler = hs.get_state_handler()
        self.distributor = hs.get_distributor()
        self.auth = hs.get_auth()
        self.hs = hs

        self.handlers.federation_handler = self.federation

        self.distributor.declare("collect_presencelike_data")

        self.handlers.room_member_handler = RoomMemberHandler(self.hs)
        self.handlers.profile_handler = ProfileHandler(self.hs)
        self.room_member_handler = self.handlers.room_member_handler

        self.ratelimiter = hs.get_ratelimiter()
        self.ratelimiter.send_message.return_value = (True, 0)

    @defer.inlineCallbacks
    def test_invite(self):
        room_id = "!foo:red"
        user_id = "@bob:red"
        target_user_id = "@red:blue"
        content = {"membership": Membership.INVITE}

        builder = self.hs.get_event_builder_factory().new({
            "type": EventTypes.Member,
            "sender": user_id,
            "state_key": target_user_id,
            "room_id": room_id,
            "content": content,
        })

        self.datastore.get_latest_events_in_room.return_value = (
            defer.succeed([])
        )

        def annotate(_):
            ctx = Mock()
            ctx.current_state = {
                (EventTypes.Member, "@alice:green"): self._create_member(
                    user_id="@alice:green",
                    room_id=room_id,
                ),
                (EventTypes.Member, "@bob:red"): self._create_member(
                    user_id="@bob:red",
                    room_id=room_id,
                ),
            }
            ctx.prev_state_events = []

            return defer.succeed(ctx)

        self.state_handler.compute_event_context.side_effect = annotate

        def add_auth(_, ctx):
            ctx.auth_events = ctx.current_state[
                (EventTypes.Member, "@bob:red")
            ]

            return defer.succeed(True)
        self.auth.add_auth_events.side_effect = add_auth

        def send_invite(domain, event):
            return defer.succeed(event)

        self.federation.send_invite.side_effect = send_invite

        room_handler = self.room_member_handler
        event, context = yield room_handler._create_new_client_event(
            builder
        )

        yield room_handler.change_membership(event, context)

        self.state_handler.compute_event_context.assert_called_once_with(
            builder
        )

        self.auth.add_auth_events.assert_called_once_with(
            builder, context
        )

        self.federation.send_invite.assert_called_once_with(
            "blue", event,
        )

        self.datastore.persist_event.assert_called_once_with(
            event, context=context,
        )
        self.notifier.on_new_room_event.assert_called_once_with(
            event, extra_users=[UserID.from_string(target_user_id)]
        )
        self.assertFalse(self.datastore.get_room.called)
        self.assertFalse(self.datastore.store_room.called)
        self.assertFalse(self.federation.get_state_for_room.called)

    @defer.inlineCallbacks
    def test_simple_join(self):
        room_id = "!foo:red"
        user_id = "@bob:red"
        user = UserID.from_string(user_id)

        join_signal_observer = Mock()
        self.distributor.observe("user_joined_room", join_signal_observer)

        builder = self.hs.get_event_builder_factory().new({
            "type": EventTypes.Member,
            "sender": user_id,
            "state_key": user_id,
            "room_id": room_id,
            "content": {"membership": Membership.JOIN},
        })

        self.datastore.get_latest_events_in_room.return_value = (
            defer.succeed([])
        )

        def annotate(_):
            ctx = Mock()
            ctx.current_state = {
                (EventTypes.Member, "@bob:red"): self._create_member(
                    user_id="@bob:red",
                    room_id=room_id,
                    membership=Membership.INVITE
                ),
            }
            ctx.prev_state_events = []

            return defer.succeed(ctx)

        self.state_handler.compute_event_context.side_effect = annotate

        def add_auth(_, ctx):
            ctx.auth_events = ctx.current_state[
                (EventTypes.Member, "@bob:red")
            ]

            return defer.succeed(True)
        self.auth.add_auth_events.side_effect = add_auth

        room_handler = self.room_member_handler
        event, context = yield room_handler._create_new_client_event(
            builder
        )

        # Actual invocation
        yield room_handler.change_membership(event, context)

        self.federation.handle_new_event.assert_called_once_with(
            event, destinations=set()
        )

        self.datastore.persist_event.assert_called_once_with(
            event, context=context
        )
        self.notifier.on_new_room_event.assert_called_once_with(
            event, extra_users=[user]
        )

        join_signal_observer.assert_called_with(
            user=user, room_id=room_id
        )

    def _create_member(self, user_id, room_id, membership=Membership.JOIN):
        builder = self.hs.get_event_builder_factory().new({
            "type": EventTypes.Member,
            "sender": user_id,
            "state_key": user_id,
            "room_id": room_id,
            "content": {"membership": membership},
        })

        return builder.build()

    @defer.inlineCallbacks
    def test_simple_leave(self):
        room_id = "!foo:red"
        user_id = "@bob:red"
        user = UserID.from_string(user_id)

        builder = self.hs.get_event_builder_factory().new({
            "type": EventTypes.Member,
            "sender": user_id,
            "state_key": user_id,
            "room_id": room_id,
            "content": {"membership": Membership.LEAVE},
        })

        self.datastore.get_latest_events_in_room.return_value = (
            defer.succeed([])
        )

        def annotate(_):
            ctx = Mock()
            ctx.current_state = {
                (EventTypes.Member, "@bob:red"): self._create_member(
                    user_id="@bob:red",
                    room_id=room_id,
                    membership=Membership.JOIN
                ),
            }
            ctx.prev_state_events = []

            return defer.succeed(ctx)

        self.state_handler.compute_event_context.side_effect = annotate

        def add_auth(_, ctx):
            ctx.auth_events = ctx.current_state[
                (EventTypes.Member, "@bob:red")
            ]

            return defer.succeed(True)
        self.auth.add_auth_events.side_effect = add_auth

        room_handler = self.room_member_handler
        event, context = yield room_handler._create_new_client_event(
            builder
        )

        leave_signal_observer = Mock()
        self.distributor.observe("user_left_room", leave_signal_observer)

        # Actual invocation
        yield room_handler.change_membership(event, context)

        self.federation.handle_new_event.assert_called_once_with(
            event, destinations=set(['red'])
        )

        self.datastore.persist_event.assert_called_once_with(
            event, context=context
        )
        self.notifier.on_new_room_event.assert_called_once_with(
            event, extra_users=[user]
        )

        leave_signal_observer.assert_called_with(
            user=user, room_id=room_id
        )


class RoomCreationTest(unittest.TestCase):

    @defer.inlineCallbacks
    def setUp(self):
        self.hostname = "red"

        hs = yield setup_test_homeserver(
            self.hostname,
            datastore=NonCallableMock(spec_set=[
                "store_room",
                "snapshot_room",
                "persist_event",
                "get_joined_hosts_for_room",
            ]),
            http_client=NonCallableMock(spec_set=[]),
            notifier=NonCallableMock(spec_set=["on_new_room_event"]),
            handlers=NonCallableMock(spec_set=[
                "room_creation_handler",
                "message_handler",
            ]),
            auth=NonCallableMock(spec_set=["check", "add_auth_events"]),
            ratelimiter=NonCallableMock(spec_set=[
                "send_message",
            ]),
        )

        self.federation = NonCallableMock(spec_set=[
            "handle_new_event",
        ])

        self.handlers = hs.get_handlers()

        self.handlers.room_creation_handler = RoomCreationHandler(hs)
        self.room_creation_handler = self.handlers.room_creation_handler

        self.message_handler = self.handlers.message_handler

        self.ratelimiter = hs.get_ratelimiter()
        self.ratelimiter.send_message.return_value = (True, 0)

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

        self.assertTrue(self.message_handler.create_and_send_event.called)

        event_dicts = [
            e[0][0]
            for e in self.message_handler.create_and_send_event.call_args_list
        ]

        self.assertTrue(len(event_dicts) > 3)

        self.assertDictContainsSubset(
            {
                "type": EventTypes.Create,
                "sender": user_id,
                "room_id": room_id,
            },
            event_dicts[0]
        )

        self.assertEqual(user_id, event_dicts[0]["content"]["creator"])

        self.assertDictContainsSubset(
            {
                "type": EventTypes.Member,
                "sender": user_id,
                "room_id": room_id,
                "state_key": user_id,
            },
            event_dicts[1]
        )

        self.assertEqual(
            Membership.JOIN,
            event_dicts[1]["content"]["membership"]
        )
