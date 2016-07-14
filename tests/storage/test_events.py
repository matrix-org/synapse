# -*- coding: utf-8 -*-
# Copyright 2015, 2016 OpenMarket Ltd
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
from synapse.types import RoomID, UserID

from tests import unittest
from twisted.internet import defer
from tests.storage.event_injector import EventInjector

from tests.utils import setup_test_homeserver


class EventsStoreTestCase(unittest.TestCase):

    @defer.inlineCallbacks
    def setUp(self):
        self.hs = yield setup_test_homeserver(
            resource_for_federation=Mock(),
            http_client=None,
        )
        self.store = self.hs.get_datastore()
        self.db_pool = self.hs.get_db_pool()
        self.message_handler = self.hs.get_handlers().message_handler
        self.event_injector = EventInjector(self.hs)

    @defer.inlineCallbacks
    def test_count_daily_messages(self):
        yield self.db_pool.runQuery("DELETE FROM stats_reporting")

        self.hs.clock.now = 100

        # Never reported before, and nothing which could be reported
        count = yield self.store.count_daily_messages()
        self.assertIsNone(count)
        count = yield self.db_pool.runQuery("SELECT COUNT(*) FROM stats_reporting")
        self.assertEqual([(0,)], count)

        # Create something to report
        room = RoomID.from_string("!abc123:test")
        user = UserID.from_string("@raccoonlover:test")
        yield self.event_injector.create_room(room)

        self.base_event = yield self._get_last_stream_token()

        yield self.event_injector.inject_message(room, user, "Raccoons are really cute")

        # Never reported before, something could be reported, but isn't because
        # it isn't old enough.
        count = yield self.store.count_daily_messages()
        self.assertIsNone(count)
        yield self._assert_stats_reporting(1, self.hs.clock.now)

        # Already reported yesterday, two new events from today.
        yield self.event_injector.inject_message(room, user, "Yeah they are!")
        yield self.event_injector.inject_message(room, user, "Incredibly!")
        self.hs.clock.now += 60 * 60 * 24
        count = yield self.store.count_daily_messages()
        self.assertEqual(2, count)  # 2 since yesterday
        yield self._assert_stats_reporting(3, self.hs.clock.now)  # 3 ever

        # Last reported too recently.
        yield self.event_injector.inject_message(room, user, "Who could disagree?")
        self.hs.clock.now += 60 * 60 * 22
        count = yield self.store.count_daily_messages()
        self.assertIsNone(count)
        yield self._assert_stats_reporting(4, self.hs.clock.now)

        # Last reported too long ago
        yield self.event_injector.inject_message(room, user, "No one.")
        self.hs.clock.now += 60 * 60 * 26
        count = yield self.store.count_daily_messages()
        self.assertIsNone(count)
        yield self._assert_stats_reporting(5, self.hs.clock.now)

        # And now let's actually report something
        yield self.event_injector.inject_message(room, user, "Indeed.")
        yield self.event_injector.inject_message(room, user, "Indeed.")
        yield self.event_injector.inject_message(room, user, "Indeed.")
        # A little over 24 hours is fine :)
        self.hs.clock.now += (60 * 60 * 24) + 50
        count = yield self.store.count_daily_messages()
        self.assertEqual(3, count)
        yield self._assert_stats_reporting(8, self.hs.clock.now)

    @defer.inlineCallbacks
    def _get_last_stream_token(self):
        rows = yield self.db_pool.runQuery(
            "SELECT stream_ordering"
            " FROM events"
            " ORDER BY stream_ordering DESC"
            " LIMIT 1"
        )
        if not rows:
            defer.returnValue(0)
        else:
            defer.returnValue(rows[0][0])

    @defer.inlineCallbacks
    def _assert_stats_reporting(self, messages, time):
        rows = yield self.db_pool.runQuery(
            "SELECT reported_stream_token, reported_time FROM stats_reporting"
        )
        self.assertEqual([(self.base_event + messages, time,)], rows)
