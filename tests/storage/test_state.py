# -*- coding: utf-8 -*-
# Copyright 2018 New Vector Ltd
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

from synapse.api.constants import EventTypes, Membership
from synapse.types import RoomID, UserID

import tests.unittest
import tests.utils


class StateStoreTestCase(tests.unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super(StateStoreTestCase, self).__init__(*args, **kwargs)
        self.store = None  # type: synapse.storage.DataStore

    @defer.inlineCallbacks
    def setUp(self):
        hs = yield tests.utils.setup_test_homeserver()

        self.store = hs.get_datastore()
        self.event_builder_factory = hs.get_event_builder_factory()
        self.event_creation_handler = hs.get_event_creation_handler()

        self.u_alice = UserID.from_string("@alice:test")
        self.u_bob = UserID.from_string("@bob:test")

        # User elsewhere on another host
        self.u_charlie = UserID.from_string("@charlie:elsewhere")

        self.room = RoomID.from_string("!abc123:test")

        yield self.store.store_room(
            self.room.to_string(),
            room_creator_user_id="@creator:text",
            is_public=True
        )

    @defer.inlineCallbacks
    def inject_state_event(self, room, sender, typ, state_key, content):
        builder = self.event_builder_factory.new({
            "type": typ,
            "sender": sender.to_string(),
            "state_key": state_key,
            "room_id": room.to_string(),
            "content": content,
        })

        event, context = yield self.event_creation_handler.create_new_client_event(
            builder
        )

        yield self.store.persist_event(event, context)

        defer.returnValue(event)

    @defer.inlineCallbacks
    def test_get_state_for_events(self):

        # this defaults to a linear DAG as each new injection defaults to whatever
        # forward extremities are currently in the DB for this room.
        (e1, c1) = yield self.inject_state_event(
            self.room, self.u_alice, EventTypes.Create, '', {},
        )
        (e2, c2) = yield self.inject_state_event(
            self.room, self.u_alice, EventTypes.Name, '', {
                "name": "test room"
            },
        )
        (e3, c3) = yield self.inject_state_event(
            self.room, self.u_alice, EventTypes.Member, self.u_alice, {
                "membership": Membership.JOIN
            },
        )
        (e4, c4) = yield self.inject_state_event(
            self.room, self.u_bob, EventTypes.Member, self.u_bob, {
                "membership": Membership.JOIN
            },
        )
        (e5, c5) = yield self.inject_state_event(
            self.room, self.u_bob, EventTypes.Member, self.u_bob, {
                "membership": Membership.LEAVE
            },
        )

        # check we get the full state as of the final event
        state = yield self.store.get_state_for_events(
            e5.event_id, None, filtered_types=None
        )

        self.assertDictEqual({
            (e1.type, e1.state_key): e1.event_id,
            (e2.type, e2.state_key): e2.event_id,
            (e3.type, e3.state_key): e3.event_id,
            # e4 is overwritten by e5
            (e5.type, e5.state_key): e5.event_id,
        }, state)

        # check we can filter to the m.room.name event (with a '' state key)
        state = yield self.store.get_state_for_events(
            e5.event_id, ((EventTypes.Name, '')), filtered_types=None
        )

        self.assertDictEqual({
            (e2.type, e2.state_key): e2.event_id,
        }, state)

        # check we can filter to the m.room.name event (with a wildcard None state key)
        state = yield self.store.get_state_for_events(
            e5.event_id, ((EventTypes.Name, None)), filtered_types=None
        )

        self.assertDictEqual({
            (e2.type, e2.state_key): e2.event_id,
        }, state)

        # check we can grab the m.room.member events (with a wildcard None state key)
        state = yield self.store.get_state_for_events(
            e5.event_id, ((EventTypes.Member, None)), filtered_types=None
        )

        self.assertDictEqual({
            (e3.type, e3.state_key): e3.event_id,
            (e5.type, e5.state_key): e5.event_id,
        }, state)

        # check we can use filter_types to grab a specific room member
        # without filtering out the other event types
        state = yield self.store.get_state_for_events(
            e5.event_id, ((EventTypes.Member, self.u_alice)),
            filtered_types=[EventTypes.Member],
        )

        self.assertDictEqual({
            (e1.type, e1.state_key): e3.event_id,
            (e2.type, e2.state_key): e3.event_id,
            (e3.type, e3.state_key): e5.event_id,
        }, state)
