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


from mock import Mock

from twisted.internet import defer

from synapse.api.constants import EventTypes, Membership
from synapse.api.room_versions import RoomVersions
from synapse.types import Requester, RoomID, UserID

from tests import unittest
from tests.utils import create_room, setup_test_homeserver


class RoomMemberStoreTestCase(unittest.TestCase):
    @defer.inlineCallbacks
    def setUp(self):
        hs = yield setup_test_homeserver(
            self.addCleanup, resource_for_federation=Mock(), http_client=None
        )
        # We can't test the RoomMemberStore on its own without the other event
        # storage logic
        self.store = hs.get_datastore()
        self.event_builder_factory = hs.get_event_builder_factory()
        self.event_creation_handler = hs.get_event_creation_handler()

        self.u_alice = UserID.from_string("@alice:test")
        self.u_bob = UserID.from_string("@bob:test")

        # User elsewhere on another host
        self.u_charlie = UserID.from_string("@charlie:elsewhere")

        self.room = RoomID.from_string("!abc123:test")

        yield create_room(hs, self.room.to_string(), self.u_alice.to_string())

    @defer.inlineCallbacks
    def inject_room_member(self, room, user, membership, replaces_state=None):
        builder = self.event_builder_factory.for_room_version(
            RoomVersions.V1,
            {
                "type": EventTypes.Member,
                "sender": user.to_string(),
                "state_key": user.to_string(),
                "room_id": room.to_string(),
                "content": {"membership": membership},
            },
        )

        event, context = yield self.event_creation_handler.create_new_client_event(
            builder
        )

        yield self.store.persist_event(event, context)

        defer.returnValue(event)

    @defer.inlineCallbacks
    def test_one_member(self):
        yield self.inject_room_member(self.room, self.u_alice, Membership.JOIN)

        self.assertEquals(
            [self.room.to_string()],
            [
                m.room_id
                for m in (
                    yield self.store.get_rooms_for_user_where_membership_is(
                        self.u_alice.to_string(), [Membership.JOIN]
                    )
                )
            ],
        )


class CurrentStateMembershipUpdateTestCase(unittest.HomeserverTestCase):
    def prepare(self, reactor, clock, homeserver):
        self.store = homeserver.get_datastore()
        self.room_creator = homeserver.get_room_creation_handler()

    def test_can_rerun_update(self):
        # First make sure we have completed all updates.
        while not self.get_success(self.store.has_completed_background_updates()):
            self.get_success(self.store.do_next_background_update(100), by=0.1)

        # Now let's create a room, which will insert a membership
        user = UserID("alice", "test")
        requester = Requester(user, None, False, None, None)
        self.get_success(self.room_creator.create_room(requester, {}))

        # Register the background update to run again.
        self.get_success(
            self.store._simple_insert(
                table="background_updates",
                values={
                    "update_name": "current_state_events_membership",
                    "progress_json": "{}",
                    "depends_on": None,
                },
            )
        )

        # ... and tell the DataStore that it hasn't finished all updates yet
        self.store._all_done = False

        # Now let's actually drive the updates to completion
        while not self.get_success(self.store.has_completed_background_updates()):
            self.get_success(self.store.do_next_background_update(100), by=0.1)
