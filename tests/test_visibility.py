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
import logging
from typing import Optional
from unittest.mock import Mock

from twisted.internet import defer
from twisted.internet.defer import succeed

from synapse.api.room_versions import RoomVersions
from synapse.events import FrozenEvent
from synapse.visibility import filter_events_for_server

import tests.unittest
from tests.utils import create_room, setup_test_homeserver

logger = logging.getLogger(__name__)

TEST_ROOM_ID = "!TEST:ROOM"


class FilterEventsForServerTestCase(tests.unittest.TestCase):
    @defer.inlineCallbacks
    def setUp(self):
        self.hs = yield setup_test_homeserver(self.addCleanup)
        self.event_creation_handler = self.hs.get_event_creation_handler()
        self.event_builder_factory = self.hs.get_event_builder_factory()
        self.storage = self.hs.get_storage()

        yield defer.ensureDeferred(create_room(self.hs, TEST_ROOM_ID, "@someone:ROOM"))

    @defer.inlineCallbacks
    def test_filtering(self):
        #
        # The events to be filtered consist of 10 membership events (it doesn't
        # really matter if they are joins or leaves, so let's make them joins).
        # One of those membership events is going to be for a user on the
        # server we are filtering for (so we can check the filtering is doing
        # the right thing).
        #

        # before we do that, we persist some other events to act as state.
        yield self.inject_visibility("@admin:hs", "joined")
        for i in range(0, 10):
            yield self.inject_room_member("@resident%i:hs" % i)

        events_to_filter = []

        for i in range(0, 10):
            user = "@user%i:%s" % (i, "test_server" if i == 5 else "other_server")
            evt = yield self.inject_room_member(user, extra_content={"a": "b"})
            events_to_filter.append(evt)

        filtered = yield defer.ensureDeferred(
            filter_events_for_server(self.storage, "test_server", events_to_filter)
        )

        # the result should be 5 redacted events, and 5 unredacted events.
        for i in range(0, 5):
            self.assertEqual(events_to_filter[i].event_id, filtered[i].event_id)
            self.assertNotIn("a", filtered[i].content)

        for i in range(5, 10):
            self.assertEqual(events_to_filter[i].event_id, filtered[i].event_id)
            self.assertEqual(filtered[i].content["a"], "b")

    @defer.inlineCallbacks
    def test_erased_user(self):
        # 4 message events, from erased and unerased users, with a membership
        # change in the middle of them.
        events_to_filter = []

        evt = yield self.inject_message("@unerased:local_hs")
        events_to_filter.append(evt)

        evt = yield self.inject_message("@erased:local_hs")
        events_to_filter.append(evt)

        evt = yield self.inject_room_member("@joiner:remote_hs")
        events_to_filter.append(evt)

        evt = yield self.inject_message("@unerased:local_hs")
        events_to_filter.append(evt)

        evt = yield self.inject_message("@erased:local_hs")
        events_to_filter.append(evt)

        # the erasey user gets erased
        yield defer.ensureDeferred(
            self.hs.get_datastore().mark_user_erased("@erased:local_hs")
        )

        # ... and the filtering happens.
        filtered = yield defer.ensureDeferred(
            filter_events_for_server(self.storage, "test_server", events_to_filter)
        )

        for i in range(0, len(events_to_filter)):
            self.assertEqual(
                events_to_filter[i].event_id,
                filtered[i].event_id,
                "Unexpected event at result position %i" % (i,),
            )

        for i in (0, 3):
            self.assertEqual(
                events_to_filter[i].content["body"],
                filtered[i].content["body"],
                "Unexpected event content at result position %i" % (i,),
            )

        for i in (1, 4):
            self.assertNotIn("body", filtered[i].content)

    @defer.inlineCallbacks
    def inject_visibility(self, user_id, visibility):
        content = {"history_visibility": visibility}
        builder = self.event_builder_factory.for_room_version(
            RoomVersions.V1,
            {
                "type": "m.room.history_visibility",
                "sender": user_id,
                "state_key": "",
                "room_id": TEST_ROOM_ID,
                "content": content,
            },
        )

        event, context = yield defer.ensureDeferred(
            self.event_creation_handler.create_new_client_event(builder)
        )
        yield defer.ensureDeferred(
            self.storage.persistence.persist_event(event, context)
        )
        return event

    @defer.inlineCallbacks
    def inject_room_member(
        self, user_id, membership="join", extra_content: Optional[dict] = None
    ):
        content = {"membership": membership}
        content.update(extra_content or {})
        builder = self.event_builder_factory.for_room_version(
            RoomVersions.V1,
            {
                "type": "m.room.member",
                "sender": user_id,
                "state_key": user_id,
                "room_id": TEST_ROOM_ID,
                "content": content,
            },
        )

        event, context = yield defer.ensureDeferred(
            self.event_creation_handler.create_new_client_event(builder)
        )

        yield defer.ensureDeferred(
            self.storage.persistence.persist_event(event, context)
        )
        return event

    @defer.inlineCallbacks
    def inject_message(self, user_id, content=None):
        if content is None:
            content = {"body": "testytest", "msgtype": "m.text"}
        builder = self.event_builder_factory.for_room_version(
            RoomVersions.V1,
            {
                "type": "m.room.message",
                "sender": user_id,
                "room_id": TEST_ROOM_ID,
                "content": content,
            },
        )

        event, context = yield defer.ensureDeferred(
            self.event_creation_handler.create_new_client_event(builder)
        )

        yield defer.ensureDeferred(
            self.storage.persistence.persist_event(event, context)
        )
        return event

    @defer.inlineCallbacks
    def test_large_room(self):
        # see what happens when we have a large room with hundreds of thousands
        # of membership events

        # As above, the events to be filtered consist of 10 membership events,
        # where one of them is for a user on the server we are filtering for.

        import cProfile
        import pstats
        import time

        # we stub out the store, because building up all that state the normal
        # way is very slow.
        test_store = _TestStore()

        # our initial state is 100000 membership events and one
        # history_visibility event.
        room_state = []

        history_visibility_evt = FrozenEvent(
            {
                "event_id": "$history_vis",
                "type": "m.room.history_visibility",
                "sender": "@resident_user_0:test.com",
                "state_key": "",
                "room_id": TEST_ROOM_ID,
                "content": {"history_visibility": "joined"},
            }
        )
        room_state.append(history_visibility_evt)
        test_store.add_event(history_visibility_evt)

        for i in range(0, 100000):
            user = "@resident_user_%i:test.com" % (i,)
            evt = FrozenEvent(
                {
                    "event_id": "$res_event_%i" % (i,),
                    "type": "m.room.member",
                    "state_key": user,
                    "sender": user,
                    "room_id": TEST_ROOM_ID,
                    "content": {"membership": "join", "extra": "zzz,"},
                }
            )
            room_state.append(evt)
            test_store.add_event(evt)

        events_to_filter = []
        for i in range(0, 10):
            user = "@user%i:%s" % (i, "test_server" if i == 5 else "other_server")
            evt = FrozenEvent(
                {
                    "event_id": "$evt%i" % (i,),
                    "type": "m.room.member",
                    "state_key": user,
                    "sender": user,
                    "room_id": TEST_ROOM_ID,
                    "content": {"membership": "join", "extra": "zzz"},
                }
            )
            events_to_filter.append(evt)
            room_state.append(evt)

            test_store.add_event(evt)
            test_store.set_state_ids_for_event(
                evt, {(e.type, e.state_key): e.event_id for e in room_state}
            )

        pr = cProfile.Profile()
        pr.enable()

        logger.info("Starting filtering")
        start = time.time()

        storage = Mock()
        storage.main = test_store
        storage.state = test_store

        filtered = yield defer.ensureDeferred(
            filter_events_for_server(test_store, "test_server", events_to_filter)
        )
        logger.info("Filtering took %f seconds", time.time() - start)

        pr.disable()
        with open("filter_events_for_server.profile", "w+") as f:
            ps = pstats.Stats(pr, stream=f).sort_stats("cumulative")
            ps.print_stats()

        # the result should be 5 redacted events, and 5 unredacted events.
        for i in range(0, 5):
            self.assertEqual(events_to_filter[i].event_id, filtered[i].event_id)
            self.assertNotIn("extra", filtered[i].content)

        for i in range(5, 10):
            self.assertEqual(events_to_filter[i].event_id, filtered[i].event_id)
            self.assertEqual(filtered[i].content["extra"], "zzz")

    test_large_room.skip = "Disabled by default because it's slow"


class _TestStore:
    """Implements a few methods of the DataStore, so that we can test
    filter_events_for_server

    """

    def __init__(self):
        # data for get_events: a map from event_id to event
        self.events = {}

        # data for get_state_ids_for_events mock: a map from event_id to
        # a map from (type_state_key) -> event_id for the state at that
        # event
        self.state_ids_for_events = {}

    def add_event(self, event):
        self.events[event.event_id] = event

    def set_state_ids_for_event(self, event, state):
        self.state_ids_for_events[event.event_id] = state

    def get_state_ids_for_events(self, events, types):
        res = {}
        include_memberships = False
        for (type, state_key) in types:
            if type == "m.room.history_visibility":
                continue
            if type != "m.room.member" or state_key is not None:
                raise RuntimeError(
                    "Unimplemented: get_state_ids with type (%s, %s)"
                    % (type, state_key)
                )
            include_memberships = True

        if include_memberships:
            for event_id in events:
                res[event_id] = self.state_ids_for_events[event_id]

        else:
            k = ("m.room.history_visibility", "")
            for event_id in events:
                hve = self.state_ids_for_events[event_id][k]
                res[event_id] = {k: hve}

        return succeed(res)

    def get_events(self, events):
        return succeed({event_id: self.events[event_id] for event_id in events})

    def are_users_erased(self, users):
        return succeed({u: False for u in users})
