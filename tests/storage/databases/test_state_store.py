# Copyright 2022 The Matrix.org Foundation C.I.C.
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
import typing
from typing import Dict, List, Sequence, Tuple
from unittest.mock import patch

from twisted.internet.defer import Deferred, ensureDeferred
from twisted.test.proto_helpers import MemoryReactor

from synapse.storage.databases.state.store import MAX_INFLIGHT_REQUESTS_PER_GROUP
from synapse.storage.state import StateFilter
from synapse.types import MutableStateMap, StateMap
from synapse.util import Clock

from tests.unittest import HomeserverTestCase

if typing.TYPE_CHECKING:
    from synapse.server import HomeServer


class StateGroupInflightCachingTestCase(HomeserverTestCase):
    def prepare(
        self, reactor: MemoryReactor, clock: Clock, homeserver: "HomeServer"
    ) -> None:
        self.state_storage = homeserver.get_storage().state
        self.state_datastore = homeserver.get_datastores().state
        # Patch out the `_get_state_groups_from_groups`.
        # This is useful because it lets us pretend we have a slow database.
        get_state_groups_patch = patch.object(
            self.state_datastore,
            "_get_state_groups_from_groups",
            self._fake_get_state_groups_from_groups,
        )
        get_state_groups_patch.start()

        self.addCleanup(get_state_groups_patch.stop)
        self.get_state_group_calls: List[
            Tuple[Tuple[int, ...], StateFilter, Deferred[Dict[int, StateMap[str]]]]
        ] = []

    def _fake_get_state_groups_from_groups(
        self, groups: Sequence[int], state_filter: StateFilter
    ) -> "Deferred[Dict[int, StateMap[str]]]":
        d: Deferred[Dict[int, StateMap[str]]] = Deferred()
        self.get_state_group_calls.append((tuple(groups), state_filter, d))
        return d

    def _complete_request_fake(
        self,
        groups: Tuple[int, ...],
        state_filter: StateFilter,
        d: "Deferred[Dict[int, StateMap[str]]]",
    ) -> None:
        """
        Assemble a fake database response and complete the database request.
        """

        result: Dict[int, StateMap[str]] = {}

        for group in groups:
            group_result: MutableStateMap[str] = {}
            result[group] = group_result

            for state_type, state_keys in state_filter.types.items():
                if state_keys is None:
                    group_result[(state_type, "a")] = "xyz"
                    group_result[(state_type, "b")] = "xyz"
                else:
                    for state_key in state_keys:
                        group_result[(state_type, state_key)] = "abc"

            if state_filter.include_others:
                group_result[("other.event.type", "state.key")] = "123"

        d.callback(result)

    def test_duplicate_requests_deduplicated(self) -> None:
        """
        Tests that duplicate requests for state are deduplicated.

        This test:
        - requests some state (state group 42, 'all' state filter)
        - requests it again, before the first request finishes
        - checks to see that only one database query was made
        - completes the database query
        - checks that both requests see the same retrieved state
        """
        req1 = ensureDeferred(
            self.state_datastore._get_state_for_group_using_inflight_cache(
                42, StateFilter.all()
            )
        )
        self.pump(by=0.1)

        # This should have gone to the database
        self.assertEqual(len(self.get_state_group_calls), 1)
        self.assertFalse(req1.called)

        req2 = ensureDeferred(
            self.state_datastore._get_state_for_group_using_inflight_cache(
                42, StateFilter.all()
            )
        )
        self.pump(by=0.1)

        # No more calls should have gone to the database
        self.assertEqual(len(self.get_state_group_calls), 1)
        self.assertFalse(req1.called)
        self.assertFalse(req2.called)

        groups, sf, d = self.get_state_group_calls[0]
        self.assertEqual(groups, (42,))
        self.assertEqual(sf, StateFilter.all())

        # Now we can complete the request
        self._complete_request_fake(groups, sf, d)

        self.assertEqual(
            self.get_success(req1), {("other.event.type", "state.key"): "123"}
        )
        self.assertEqual(
            self.get_success(req2), {("other.event.type", "state.key"): "123"}
        )

    def test_inflight_requests_capped(self) -> None:
        """
        Tests that the number of in-flight requests is capped to 5.

        - requests several pieces of state separately
          (5 to hit the limit, 1 to 'shunt out', another that
        - checks to see that the torrent of requests is shunted out by
          rewriting one of the filters as the 'all' state filter
        - requests after that one do not cause any additional queries
        """
        CAP_COUNT = 5

        reqs = []

        # Request 7 different keys (1..=7) of the `some.state` type.
        for req_id in range(CAP_COUNT + 2):
            reqs.append(
                ensureDeferred(
                    self.state_datastore._get_state_for_group_using_inflight_cache(
                        42,
                        StateFilter.freeze(
                            {"some.state": {str(req_id + 1)}}, include_others=False
                        ),
                    )
                )
            )
        self.pump(by=0.1)

        # There should only be 6 calls to the database, not 7.
        self.assertEqual(len(self.get_state_group_calls), CAP_COUNT + 1)

        # Assert that the first 5 are exact requests for the individual pieces
        # wanted
        for req_id in range(CAP_COUNT):
            groups, sf, d = self.get_state_group_calls[req_id]
            self.assertEqual(
                sf,
                StateFilter.freeze(
                    {"some.state": {str(req_id + 1)}}, include_others=False
                ),
            )

        # The 6th request should be the 'all' state filter
        groups, sf, d = self.get_state_group_calls[CAP_COUNT]
        self.assertEqual(sf, StateFilter.all())

        # Complete the queries and check which requests complete as a result
        for req_id in range(CAP_COUNT):
            # This request should not have been completed yet
            self.assertFalse(reqs[req_id].called)

            groups, sf, d = self.get_state_group_calls[req_id]
            self._complete_request_fake(groups, sf, d)

            # This should have only completed this one request
            self.assertTrue(reqs[req_id].called)

        # Now complete the final query; the last 2 requests should complete
        # as a result
        self.assertFalse(reqs[CAP_COUNT].called)
        self.assertFalse(reqs[CAP_COUNT + 1].called)
        groups, sf, d = self.get_state_group_calls[CAP_COUNT]
        self._complete_request_fake(groups, sf, d)
        self.assertTrue(reqs[CAP_COUNT].called)
        self.assertTrue(reqs[CAP_COUNT + 1].called)
