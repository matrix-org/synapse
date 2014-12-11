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
from tests import unittest

from synapse.api.events.room import (
    RoomMemberEvent,
)
from synapse.api.constants import Membership
from synapse.handlers.room import RoomMemberHandler, RoomCreationHandler
from synapse.handlers.profile import ProfileHandler
from synapse.server import HomeServer
from ..utils import MockKey

from mock import Mock, NonCallableMock


class RoomMemberHandlerTestCase(unittest.TestCase):

    def setUp(self):
        self.mock_config = NonCallableMock()
        self.mock_config.signing_key = [MockKey()]

        self.hostname = "red"
        hs = HomeServer(
            self.hostname,
            db_pool=None,
            ratelimiter=NonCallableMock(spec_set=[
                "send_message",
            ]),
            datastore=NonCallableMock(spec_set=[
                "persist_event",
                "get_room_member",
                "get_room",
                "store_room",
                "snapshot_room",
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
                "annotate_event_with_state",
                "get_current_state",
            ]),
            config=self.mock_config,
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

        self.snapshot = Mock()
        self.datastore.snapshot_room.return_value = self.snapshot

        self.ratelimiter = hs.get_ratelimiter()
        self.ratelimiter.send_message.return_value = (True, 0)

    @defer.inlineCallbacks
    def test_invite(self):
        room_id = "!foo:red"
        user_id = "@bob:red"
        target_user_id = "@red:blue"
        content = {"membership": Membership.INVITE}

        event = self.hs.get_event_factory().create_event(
            etype=RoomMemberEvent.TYPE,
            user_id=user_id,
            state_key=target_user_id,
            room_id=room_id,
            membership=Membership.INVITE,
            content=content,
        )

        self.auth.check_host_in_room.return_value = defer.succeed(True)

        store_id = "store_id_fooo"
        self.datastore.persist_event.return_value = defer.succeed(store_id)

        self.datastore.get_room_member.return_value = defer.succeed(None)

        event.old_state_events = {
            (RoomMemberEvent.TYPE, "@alice:green"): self._create_member(
                user_id="@alice:green",
                room_id=room_id,
            ),
            (RoomMemberEvent.TYPE, "@bob:red"): self._create_member(
                user_id="@bob:red",
                room_id=room_id,
            ),
        }

        event.state_events = event.old_state_events
        event.state_events[(RoomMemberEvent.TYPE, target_user_id)] = event

        # Actual invocation
        yield self.room_member_handler.change_membership(event)

        self.federation.handle_new_event.assert_called_once_with(
            event, self.snapshot,
        )

        self.assertEquals(
            set(["red", "green"]),
            set(event.destinations)
        )

        self.datastore.persist_event.assert_called_once_with(
            event
        )
        self.notifier.on_new_room_event.assert_called_once_with(
            event, extra_users=[self.hs.parse_userid(target_user_id)]
        )
        self.assertFalse(self.datastore.get_room.called)
        self.assertFalse(self.datastore.store_room.called)
        self.assertFalse(self.federation.get_state_for_room.called)

    @defer.inlineCallbacks
    def test_simple_join(self):
        room_id = "!foo:red"
        user_id = "@bob:red"
        user = self.hs.parse_userid(user_id)

        event = self._create_member(
            user_id=user_id,
            room_id=room_id,
        )

        self.auth.check_host_in_room.return_value = defer.succeed(True)

        store_id = "store_id_fooo"
        self.datastore.persist_event.return_value = defer.succeed(store_id)
        self.datastore.get_room.return_value = defer.succeed(1)  # Not None.

        prev_state = NonCallableMock()
        prev_state.membership = Membership.INVITE
        prev_state.sender = "@foo:red"
        self.datastore.get_room_member.return_value = defer.succeed(prev_state)

        join_signal_observer = Mock()
        self.distributor.observe("user_joined_room", join_signal_observer)

        event.state_events = {
            (RoomMemberEvent.TYPE, "@alice:green"): self._create_member(
                user_id="@alice:green",
                room_id=room_id,
            ),
            (RoomMemberEvent.TYPE, user_id): event,
        }

        event.old_state_events = {
            (RoomMemberEvent.TYPE, "@alice:green"): self._create_member(
                user_id="@alice:green",
                room_id=room_id,
            ),
        }

        event.state_events = event.old_state_events
        event.state_events[(RoomMemberEvent.TYPE, user_id)] = event

        # Actual invocation
        yield self.room_member_handler.change_membership(event)

        self.federation.handle_new_event.assert_called_once_with(
            event, self.snapshot
        )

        self.assertEquals(
            set(["red", "green"]),
            set(event.destinations)
        )

        self.datastore.persist_event.assert_called_once_with(
            event
        )
        self.notifier.on_new_room_event.assert_called_once_with(
            event, extra_users=[user]
        )

        join_signal_observer.assert_called_with(
            user=user, room_id=room_id
        )

    @defer.inlineCallbacks
    def test_simple_leave(self):
        room_id = "!foo:red"
        user_id = "@bob:red"
        user = self.hs.parse_userid(user_id)

        event = self._create_member(
            user_id=user_id,
            room_id=room_id,
            membership=Membership.LEAVE,
        )

        prev_state = NonCallableMock()
        prev_state.membership = Membership.JOIN
        prev_state.sender = user_id
        self.datastore.get_room_member.return_value = defer.succeed(prev_state)

        event.state_events = {
            (RoomMemberEvent.TYPE, user_id): event,
        }

        event.old_state_events = {
            (RoomMemberEvent.TYPE, user_id): self._create_member(
                user_id=user_id,
                room_id=room_id,
            ),
        }

        leave_signal_observer = Mock()
        self.distributor.observe("user_left_room", leave_signal_observer)

        # Actual invocation
        yield self.room_member_handler.change_membership(event)

        leave_signal_observer.assert_called_with(
            user=user, room_id=room_id
        )

    def _create_member(self, user_id, room_id, membership=Membership.JOIN):
        return self.hs.get_event_factory().create_event(
            etype=RoomMemberEvent.TYPE,
            user_id=user_id,
            state_key=user_id,
            room_id=room_id,
            membership=membership,
            content={"membership": membership},
        )


class RoomCreationTest(unittest.TestCase):

    def setUp(self):
        self.hostname = "red"

        self.mock_config = NonCallableMock()
        self.mock_config.signing_key = [MockKey()]

        hs = HomeServer(
            self.hostname,
            db_pool=None,
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
                "room_member_handler",
                "federation_handler",
            ]),
            auth=NonCallableMock(spec_set=["check", "add_auth_events"]),
            state_handler=NonCallableMock(spec_set=[
                "annotate_event_with_state",
            ]),
            ratelimiter=NonCallableMock(spec_set=[
                "send_message",
            ]),
            config=self.mock_config,
        )

        self.federation = NonCallableMock(spec_set=[
            "handle_new_event",
        ])

        self.datastore = hs.get_datastore()
        self.handlers = hs.get_handlers()
        self.notifier = hs.get_notifier()
        self.state_handler = hs.get_state_handler()
        self.hs = hs

        self.handlers.federation_handler = self.federation

        self.handlers.room_creation_handler = RoomCreationHandler(self.hs)
        self.room_creation_handler = self.handlers.room_creation_handler

        self.handlers.room_member_handler = NonCallableMock(spec_set=[
            "change_membership"
        ])
        self.room_member_handler = self.handlers.room_member_handler

        def annotate(event):
            event.state_events = {}
            return defer.succeed(None)
        self.state_handler.annotate_event_with_state.side_effect = annotate

        def hosts(room):
            return defer.succeed([])
        self.datastore.get_joined_hosts_for_room.side_effect = hosts

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

        self.assertTrue(self.room_member_handler.change_membership.called)
        join_event = self.room_member_handler.change_membership.call_args[0][0]

        self.assertEquals(RoomMemberEvent.TYPE, join_event.type)
        self.assertEquals(room_id, join_event.room_id)
        self.assertEquals(user_id, join_event.user_id)
        self.assertEquals(user_id, join_event.state_key)

        self.assertTrue(self.state_handler.annotate_event_with_state.called)

        self.assertTrue(self.federation.handle_new_event.called)
