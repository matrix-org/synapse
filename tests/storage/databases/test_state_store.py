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

from synapse.api.constants import EventTypes
from twisted.internet.defer import Deferred, ensureDeferred
from twisted.test.proto_helpers import MemoryReactor

from synapse.storage.state import StateFilter
from synapse.types import StateMap
from synapse.util import Clock

from tests.unittest import HomeserverTestCase

if typing.TYPE_CHECKING:
    from synapse.server import HomeServer

# StateFilter for ALL non-m.room.member state events
ALL_NON_MEMBERS_STATE_FILTER = StateFilter.freeze(
    types={
        EventTypes.Member: set()
    },
    include_others=True,
)

FAKE_STATE = {
    (EventTypes.Member, "@alice:test"): "join",
    (EventTypes.Member, "@bob:test"): "leave",
    (EventTypes.Member, "@charlie:test"): "invite",
    ("test.type", "a"): "AAA",
    ("test.type", "b"): "BBB",
    ("other.event.type", "state.key"): "123"
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
        d.callback({
            group: state_filter.filter_state(FAKE_STATE)
            for group in groups
        })

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
            self.get_success(req1), FAKE_STATE
        )
        self.assertEqual(
            self.get_success(req2), FAKE_STATE
        )


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
            self.get_success(req1), {("test.type", "a"): "AAA", ("test.type", "b"): "BBB"}
        )
        self.assertEqual(
            self.get_success(req2), {("test.type", "b"): "BBB"}
        )
