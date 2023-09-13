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
from twisted.internet.defer import ensureDeferred

from synapse.rest.client import room

from tests.replication._base import BaseMultiWorkerStreamTestCase


class PartialStateStreamsTestCase(BaseMultiWorkerStreamTestCase):
    servlets = [room.register_servlets]
    hijack_auth = True
    user_id = "@bob:test"

    def setUp(self) -> None:
        super().setUp()
        self.store = self.hs.get_datastores().main

    def test_un_partial_stated_room_unblocks_over_replication(self) -> None:
        """
        Tests that, when a room is un-partial-stated on another worker,
        pending calls to `await_full_state` get unblocked.
        """

        # Make a room.
        room_id = self.helper.create_room_as("@bob:test")
        # Mark the room as partial-stated.
        self.get_success(
            self.store.store_partial_state_room(room_id, {"serv1", "serv2"}, 0, "serv1")
        )

        worker = self.make_worker_hs("synapse.app.generic_worker")

        # On the worker, attempt to get the current hosts in the room
        d = ensureDeferred(
            worker.get_storage_controllers().state.get_current_hosts_in_room(room_id)
        )

        self.reactor.advance(0.1)

        # This should block
        self.assertFalse(
            d.called, "get_current_hosts_in_room/await_full_state did not block"
        )

        # On the master, clear the partial state flag.
        self.get_success(self.store.clear_partial_state_room(room_id))

        self.reactor.advance(0.1)

        # The worker should have unblocked
        self.assertTrue(
            d.called, "get_current_hosts_in_room/await_full_state did not unblock"
        )
