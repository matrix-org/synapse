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

from twisted.internet import defer

from synapse.visibility import filter_events_for_server
from tests import unittest
from tests.utils import setup_test_homeserver

logger = logging.getLogger(__name__)

TEST_ROOM_ID = "!TEST:ROOM"


class FilterEventsForServerTestCase(unittest.TestCase):
    @defer.inlineCallbacks
    def setUp(self):
        self.hs = yield setup_test_homeserver()
        self.event_creation_handler = self.hs.get_event_creation_handler()
        self.event_builder_factory = self.hs.get_event_builder_factory()
        self.store = self.hs.get_datastore()

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
        self.inject_visibility("@admin:hs", "joined")
        for i in range(0, 10):
            yield self.inject_room_member("@resident%i:hs" % i)

        events_to_filter = []

        for i in range(0, 10):
            user = "@user%i:%s" % (
                i, "test_server" if i == 5 else "other_server"
            )
            evt = yield self.inject_room_member(user, extra_content={"a": "b"})
            events_to_filter.append(evt)

        filtered = yield filter_events_for_server(
            self.store, "test_server", events_to_filter,
        )

        # the result should be 5 redacted events, and 5 unredacted events.
        for i in range(0, 5):
            self.assertEqual(events_to_filter[i].event_id, filtered[i].event_id)
            self.assertNotIn("a", filtered[i].content)

        for i in range(5, 10):
            self.assertEqual(events_to_filter[i].event_id, filtered[i].event_id)
            self.assertEqual(filtered[i].content["a"], "b")

    @defer.inlineCallbacks
    def inject_visibility(self, user_id, visibility):
        content = {"history_visibility": visibility}
        builder = self.event_builder_factory.new({
            "type": "m.room.history_visibility",
            "sender": user_id,
            "state_key": "",
            "room_id": TEST_ROOM_ID,
            "content": content,
        })

        event, context = yield self.event_creation_handler.create_new_client_event(
            builder
        )
        yield self.hs.get_datastore().persist_event(event, context)
        defer.returnValue(event)

    @defer.inlineCallbacks
    def inject_room_member(self, user_id, membership="join", extra_content={}):
        content = {"membership": membership}
        content.update(extra_content)
        builder = self.event_builder_factory.new({
            "type": "m.room.member",
            "sender": user_id,
            "state_key": user_id,
            "room_id": TEST_ROOM_ID,
            "content": content,
        })

        event, context = yield self.event_creation_handler.create_new_client_event(
            builder
        )

        yield self.hs.get_datastore().persist_event(event, context)
        defer.returnValue(event)
