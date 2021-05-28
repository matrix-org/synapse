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
from synapse.storage.databases.main.events_worker import EventsWorkerStore

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
