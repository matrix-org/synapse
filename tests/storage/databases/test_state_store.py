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

from parameterized import parameterized

from twisted.internet.defer import Deferred, ensureDeferred
from twisted.test.proto_helpers import MemoryReactor

from synapse.api.constants import EventTypes
from synapse.storage.databases.state.store import (
    MAX_INFLIGHT_REQUESTS_PER_GROUP,
    state_filter_rough_size_comparator,
)
from synapse.storage.state import StateFilter
from synapse.types import StateMap
from synapse.util import Clock

from tests.unittest import HomeserverTestCase

if typing.TYPE_CHECKING:
    from synapse.server import HomeServer

# StateFilter for ALL non-m.room.member state events
ALL_NON_MEMBERS_STATE_FILTER = StateFilter.freeze(
    types={EventTypes.Member: set()},
    include_others=True,
)

FAKE_STATE = {
    (EventTypes.Member, "@alice:test"): "join",
    (EventTypes.Member, "@bob:test"): "leave",
    (EventTypes.Member, "@charlie:test"): "invite",
    ("test.type", "a"): "AAA",
    ("test.type", "b"): "BBB",
    ("other.event.type", "state.key"): "123",
}


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

        # Return a filtered copy of the fake state
        d.callback({group: state_filter.filter_state(FAKE_STATE) for group in groups})

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

        self.assertEqual(self.get_success(req1), FAKE_STATE)
        self.assertEqual(self.get_success(req2), FAKE_STATE)

    def test_smaller_request_deduplicated(self) -> None:
        """
        Tests that duplicate requests for state are deduplicated.

        This test:
        - requests some state (state group 42, 'all' state filter)
        - requests a subset of that state, before the first request finishes
        - checks to see that only one database query was made
        - completes the database query
        - checks that both requests see the correct retrieved state
        """
        req1 = ensureDeferred(
            self.state_datastore._get_state_for_group_using_inflight_cache(
                42, StateFilter.from_types((("test.type", None),))
            )
        )
        self.pump(by=0.1)

        # This should have gone to the database
        self.assertEqual(len(self.get_state_group_calls), 1)
        self.assertFalse(req1.called)

        req2 = ensureDeferred(
            self.state_datastore._get_state_for_group_using_inflight_cache(
                42, StateFilter.from_types((("test.type", "b"),))
            )
        )
        self.pump(by=0.1)

        # No more calls should have gone to the database, because the second
        # request was already in the in-flight cache!
        self.assertEqual(len(self.get_state_group_calls), 1)
        self.assertFalse(req1.called)
        self.assertFalse(req2.called)

        groups, sf, d = self.get_state_group_calls[0]
        self.assertEqual(groups, (42,))
        # The state filter is expanded internally for increased cache hit rate,
        # so we the database sees a wider state filter than requested.
        self.assertEqual(sf, ALL_NON_MEMBERS_STATE_FILTER)

        # Now we can complete the request
        self._complete_request_fake(groups, sf, d)

        self.assertEqual(
            self.get_success(req1),
            {("test.type", "a"): "AAA", ("test.type", "b"): "BBB"},
        )
        self.assertEqual(self.get_success(req2), {("test.type", "b"): "BBB"})

    def test_partially_overlapping_request_deduplicated(self) -> None:
        """
        Tests that partially-overlapping requests are partially deduplicated.

        This test:
        - requests a single type of wildcard state
          (This is internally expanded to be all non-member state)
        - requests the entire state in parallel
        - checks to see that two database queries were made, but that the second
          one is only for member state.
        - completes the database queries
        - checks that both requests have the correct result.
        """

        req1 = ensureDeferred(
            self.state_datastore._get_state_for_group_using_inflight_cache(
                42, StateFilter.from_types((("test.type", None),))
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

        # Because it only partially overlaps, this also went to the database
        self.assertEqual(len(self.get_state_group_calls), 2)
        self.assertFalse(req1.called)
        self.assertFalse(req2.called)

        # First request:
        groups, sf, d = self.get_state_group_calls[0]
        self.assertEqual(groups, (42,))
        # The state filter is expanded internally for increased cache hit rate,
        # so we the database sees a wider state filter than requested.
        self.assertEqual(sf, ALL_NON_MEMBERS_STATE_FILTER)
        self._complete_request_fake(groups, sf, d)

        # Second request:
        groups, sf, d = self.get_state_group_calls[1]
        self.assertEqual(groups, (42,))
        # The state filter is narrowed to only request membership state, because
        # the remainder of the state is already being queried in the first request!
        self.assertEqual(
            sf, StateFilter.freeze({EventTypes.Member: None}, include_others=False)
        )
        self._complete_request_fake(groups, sf, d)

        # Check the results are correct
        self.assertEqual(
            self.get_success(req1),
            {("test.type", "a"): "AAA", ("test.type", "b"): "BBB"},
        )
        self.assertEqual(self.get_success(req2), FAKE_STATE)

    def test_in_flight_requests_stop_being_in_flight(self) -> None:
        """
        Tests that in-flight request deduplication doesn't somehow 'hold on'
        to completed requests: once they're done, they're taken out of the
        in-flight cache.
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

        # Complete the request right away.
        self._complete_request_fake(*self.get_state_group_calls[0])
        self.assertTrue(req1.called)

        # Send off another request
        req2 = ensureDeferred(
            self.state_datastore._get_state_for_group_using_inflight_cache(
                42, StateFilter.all()
            )
        )
        self.pump(by=0.1)

        # It should have gone to the database again, because the previous request
        # isn't in-flight and therefore isn't available for deduplication.
        self.assertEqual(len(self.get_state_group_calls), 2)
        self.assertFalse(req2.called)

        # Complete the request right away.
        self._complete_request_fake(*self.get_state_group_calls[1])
        self.assertTrue(req2.called)
        groups, sf, d = self.get_state_group_calls[0]

        self.assertEqual(self.get_success(req1), FAKE_STATE)
        self.assertEqual(self.get_success(req2), FAKE_STATE)

    def test_inflight_requests_capped(self) -> None:
        """
        Tests that the number of in-flight requests is capped to 5.

        - requests several pieces of state separately
          (5 to hit the limit, 1 to 'shunt out', another that comes after the
          group has been 'shunted out')
        - checks to see that the torrent of requests is shunted out by
          rewriting one of the filters as the 'all' state filter
        - requests after that one do not cause any additional queries
        """
        # 5 at the time of writing.
        CAP_COUNT = MAX_INFLIGHT_REQUESTS_PER_GROUP

        reqs = []

        # Request 7 different keys (1 to 7) of the `some.state` type.
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

    @parameterized.expand([(False,), (True,)])
    def test_ordering_of_request_reuse(self, reverse: bool) -> None:
        """
        Tests that 'larger' in-flight requests are ordered first.

        This is mostly a design decision in order to prevent a request from
        hanging on to multiple queries when it would have been sufficient to
        hang on to only one bigger query.

        The 'size' of a state filter is a rough heuristic.

        - requests two pieces of state, one 'larger' than the other, but each
          spawning a query
        - requests a third piece of state
        - completes the larger of the first two queries
        - checks that the third request gets completed (and doesn't needlessly
          wait for the other query)

        Parameters:
            reverse: whether to reverse the order of the initial requests, to ensure
                     that the effect doesn't depend on the order of request submission.
        """

        # We add in an extra state type to make sure that both requests spawn
        # queries which are not optimised out.
        state_filters = [
            StateFilter.freeze(
                {"state.type": {"A"}, "other.state.type": {"a"}}, include_others=False
            ),
            StateFilter.freeze(
                {
                    "state.type": None,
                    "other.state.type": {"b"},
                    # The current rough size comparator uses the number of state types
                    # as an indicator of size.
                    # To influence it to make this state filter bigger than the previous one,
                    # we add another dummy state type.
                    "extra.state.type": {"c"},
                },
                include_others=False,
            ),
        ]

        if reverse:
            # For fairness, we perform one test run with the list reversed.
            state_filters.reverse()
            smallest_state_filter_idx = 1
            biggest_state_filter_idx = 0
        else:
            smallest_state_filter_idx = 0
            biggest_state_filter_idx = 1

        # This assertion is for our own sanity more than anything else.
        self.assertGreater(
            state_filter_rough_size_comparator(state_filters[biggest_state_filter_idx]),
            state_filter_rough_size_comparator(
                state_filters[smallest_state_filter_idx]
            ),
            "Test invalid: bigger state filter is not actually bigger.",
        )

        # Spawn the initial two requests
        for state_filter in state_filters:
            ensureDeferred(
                self.state_datastore._get_state_for_group_using_inflight_cache(
                    42,
                    state_filter,
                )
            )

        # Spawn a third request
        req = ensureDeferred(
            self.state_datastore._get_state_for_group_using_inflight_cache(
                42,
                StateFilter.freeze(
                    {
                        "state.type": {"A"},
                    },
                    include_others=False,
                ),
            )
        )
        self.pump(by=0.1)

        self.assertFalse(req.called)

        # Complete the largest request's query to make sure that the final request
        # only waits for that one (and doesn't needlessly wait for both queries)
        self._complete_request_fake(
            *self.get_state_group_calls[biggest_state_filter_idx]
        )

        # That should have been sufficient to complete the third request
        self.assertTrue(req.called)
