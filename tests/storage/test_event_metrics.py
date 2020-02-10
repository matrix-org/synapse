# -*- coding: utf-8 -*-
# Copyright 2019 The Matrix.org Foundation C.I.C.
#
# Licensed under the Apache License, Version 2.0 (the 'License');
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an 'AS IS' BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from synapse.metrics import REGISTRY
from synapse.types import Requester, UserID

from tests.unittest import HomeserverTestCase


class ExtremStatisticsTestCase(HomeserverTestCase):
    def test_exposed_to_prometheus(self):
        """
        Forward extremity counts are exposed via Prometheus.
        """
        room_creator = self.hs.get_room_creation_handler()

        user = UserID("alice", "test")
        requester = Requester(user, None, False, None, None)

        # Real events, forward extremities
        events = [(3, 2), (6, 2), (4, 6)]

        for event_count, extrems in events:
            info = self.get_success(room_creator.create_room(requester, {}))
            room_id = info["room_id"]

            last_event = None

            # Make a real event chain
            for i in range(event_count):
                ev = self.create_and_send_event(room_id, user, False, last_event)
                last_event = [ev]

            # Sprinkle in some extremities
            for i in range(extrems):
                ev = self.create_and_send_event(room_id, user, False, last_event)

        # Let it run for a while, then pull out the statistics from the
        # Prometheus client registry
        self.reactor.advance(60 * 60 * 1000)
        self.pump(1)

        items = list(
            filter(
                lambda x: x.name == "synapse_forward_extremities",
                list(REGISTRY.collect()),
            )
        )

        # Check the values are what we want
        buckets = {}
        _count = 0
        _sum = 0

        for i in items[0].samples:
            if i[0].endswith("_bucket"):
                buckets[i[1]['le']] = i[2]
            elif i[0].endswith("_count"):
                _count = i[2]
            elif i[0].endswith("_sum"):
                _sum = i[2]

        # 3 buckets, 2 with 2 extrems, 1 with 6 extrems (bucketed as 7), and
        # +Inf which is all
        self.assertEqual(
            buckets,
            {
                1.0: 0,
                2.0: 2,
                3.0: 0,
                5.0: 0,
                7.0: 1,
                10.0: 0,
                15.0: 0,
                20.0: 0,
                50.0: 0,
                100.0: 0,
                200.0: 0,
                500.0: 0,
                "+Inf": 3,
            },
        )
        # 3 rooms, with 10 total events
        self.assertEqual(_count, 3)
        self.assertEqual(_sum, 10)
