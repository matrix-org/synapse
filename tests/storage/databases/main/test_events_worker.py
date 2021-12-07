# Copyright 2021 The Matrix.org Foundation C.I.C.
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
import json

from synapse.logging.context import LoggingContext
from synapse.rest import admin
from synapse.rest.client import login, room
from synapse.storage.databases.main.events_worker import EventsWorkerStore
from synapse.util.async_helpers import yieldable_gather_results

from tests import unittest


class HaveSeenEventsTestCase(unittest.HomeserverTestCase):
    def prepare(self, reactor, clock, hs):
        self.store: EventsWorkerStore = hs.get_datastore()

        # insert some test data
        for rid in ("room1", "room2"):
            self.get_success(
                self.store.db_pool.simple_insert(
                    "rooms",
                    {"room_id": rid, "room_version": 4},
                )
            )

        for idx, (rid, eid) in enumerate(
            (
                ("room1", "event10"),
                ("room1", "event11"),
                ("room1", "event12"),
                ("room2", "event20"),
            )
        ):
            self.get_success(
                self.store.db_pool.simple_insert(
                    "events",
                    {
                        "event_id": eid,
                        "room_id": rid,
                        "topological_ordering": idx,
                        "stream_ordering": idx,
                        "type": "test",
                        "processed": True,
                        "outlier": False,
                    },
                )
            )
            self.get_success(
                self.store.db_pool.simple_insert(
                    "event_json",
                    {
                        "event_id": eid,
                        "room_id": rid,
                        "json": json.dumps({"type": "test", "room_id": rid}),
                        "internal_metadata": "{}",
                        "format_version": 3,
                    },
                )
            )

    def test_simple(self):
        with LoggingContext(name="test") as ctx:
            res = self.get_success(
                self.store.have_seen_events("room1", ["event10", "event19"])
            )
            self.assertEquals(res, {"event10"})

            # that should result in a single db query
            self.assertEquals(ctx.get_resource_usage().db_txn_count, 1)

        # a second lookup of the same events should cause no queries
        with LoggingContext(name="test") as ctx:
            res = self.get_success(
                self.store.have_seen_events("room1", ["event10", "event19"])
            )
            self.assertEquals(res, {"event10"})
            self.assertEquals(ctx.get_resource_usage().db_txn_count, 0)

    def test_query_via_event_cache(self):
        # fetch an event into the event cache
        self.get_success(self.store.get_event("event10"))

        # looking it up should now cause no db hits
        with LoggingContext(name="test") as ctx:
            res = self.get_success(self.store.have_seen_events("room1", ["event10"]))
            self.assertEquals(res, {"event10"})
            self.assertEquals(ctx.get_resource_usage().db_txn_count, 0)


class EventCacheTestCase(unittest.HomeserverTestCase):
    """Test that the various layers of event cache works."""

    servlets = [
        admin.register_servlets,
        room.register_servlets,
        login.register_servlets,
    ]

    def prepare(self, reactor, clock, hs):
        self.store: EventsWorkerStore = hs.get_datastore()

        self.user = self.register_user("user", "pass")
        self.token = self.login(self.user, "pass")

        self.room = self.helper.create_room_as(self.user, tok=self.token)

        res = self.helper.send(self.room, tok=self.token)
        self.event_id = res["event_id"]

        # Reset the event cache so the tests start with it empty
        self.store._get_event_cache.clear()

    def test_simple(self):
        """Test that we cache events that we pull from the DB."""

        with LoggingContext("test") as ctx:
            self.get_success(self.store.get_event(self.event_id))

            # We should have fetched the event from the DB
            self.assertEqual(ctx.get_resource_usage().evt_db_fetch_count, 1)

    def test_dedupe(self):
        """Test that if we request the same event multiple times we only pull it
        out once.
        """

        with LoggingContext("test") as ctx:
            d = yieldable_gather_results(
                self.store.get_event, [self.event_id, self.event_id]
            )
            self.get_success(d)

            # We should have fetched the event from the DB
            self.assertEqual(ctx.get_resource_usage().evt_db_fetch_count, 1)
