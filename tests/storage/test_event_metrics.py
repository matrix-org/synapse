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

from synapse.metrics import REGISTRY, generate_latest
from synapse.types import UserID, create_requester

from tests.unittest import HomeserverTestCase


class ExtremStatisticsTestCase(HomeserverTestCase):
    def test_exposed_to_prometheus(self):
        """
        Forward extremity counts are exposed via Prometheus.
        """
        room_creator = self.hs.get_room_creation_handler()

        user = UserID("alice", "test")
        requester = create_requester(user)

        # Real events, forward extremities
        events = [(3, 2), (6, 2), (4, 6)]

        for event_count, extrems in events:
            info, _ = self.get_success(room_creator.create_room(requester, {}))
            room_id = info["room_id"]

            last_event = None

            # Make a real event chain
            for _ in range(event_count):
                ev = self.create_and_send_event(room_id, user, False, last_event)
                last_event = [ev]

            # Sprinkle in some extremities
            for _ in range(extrems):
                ev = self.create_and_send_event(room_id, user, False, last_event)

        # Let it run for a while, then pull out the statistics from the
        # Prometheus client registry
        self.reactor.advance(60 * 60 * 1000)
        self.pump(1)

        items = list(
            filter(
                lambda x: b"synapse_forward_extremities_" in x,
                generate_latest(REGISTRY, emit_help=False).split(b"\n"),
            )
        )

        expected = [
            b'synapse_forward_extremities_bucket{le="1.0"} 0.0',
            b'synapse_forward_extremities_bucket{le="2.0"} 2.0',
            b'synapse_forward_extremities_bucket{le="3.0"} 2.0',
            b'synapse_forward_extremities_bucket{le="5.0"} 2.0',
            b'synapse_forward_extremities_bucket{le="7.0"} 3.0',
            b'synapse_forward_extremities_bucket{le="10.0"} 3.0',
            b'synapse_forward_extremities_bucket{le="15.0"} 3.0',
            b'synapse_forward_extremities_bucket{le="20.0"} 3.0',
            b'synapse_forward_extremities_bucket{le="50.0"} 3.0',
            b'synapse_forward_extremities_bucket{le="100.0"} 3.0',
            b'synapse_forward_extremities_bucket{le="200.0"} 3.0',
            b'synapse_forward_extremities_bucket{le="500.0"} 3.0',
            # per https://docs.google.com/document/d/1KwV0mAXwwbvvifBvDKH_LU1YjyXE_wxCkHNoCGq1GX0/edit#heading=h.wghdjzzh72j9,
            # "inf" is valid: "this includes variants such as inf"
            b'synapse_forward_extremities_bucket{le="inf"} 3.0',
            b"# TYPE synapse_forward_extremities_gcount gauge",
            b"synapse_forward_extremities_gcount 3.0",
            b"# TYPE synapse_forward_extremities_gsum gauge",
            b"synapse_forward_extremities_gsum 10.0",
        ]
        self.assertEqual(items, expected)
