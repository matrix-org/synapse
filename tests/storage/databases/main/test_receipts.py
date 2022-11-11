# Copyright 2022 The Matrix.org Foundation C.I.C.
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

from typing import Any, Dict

from twisted.test.proto_helpers import MemoryReactor

from synapse.rest import admin
from synapse.rest.client import login, room
from synapse.server import HomeServer
from synapse.storage.database import LoggingTransaction
from synapse.util import Clock

from tests.unittest import HomeserverTestCase


class ReceiptsBackgroundUpdateStoreTestCase(HomeserverTestCase):

    servlets = [
        admin.register_servlets,
        room.register_servlets,
        login.register_servlets,
    ]

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer):
        self.store = hs.get_datastores().main
        self.user_id = self.register_user("foo", "pass")
        self.token = self.login("foo", "pass")
        self.room_id = self.helper.create_room_as(self.user_id, tok=self.token)
        self.other_room_id = self.helper.create_room_as(self.user_id, tok=self.token)

    def _test_background_receipts_unique_index(
        self,
        update_name: str,
        index_name: str,
        table: str,
        values: Dict[str, Any],
    ):
        """Test that the background update to uniqueify non-thread receipts in
        the given receipts table works properly.
        """
        # First, undo the background update.
        def drop_receipts_unique_index(txn: LoggingTransaction) -> None:
            txn.execute(f"DROP INDEX IF EXISTS {index_name}")

        self.get_success(
            self.store.db_pool.runInteraction(
                "drop_receipts_unique_index",
                drop_receipts_unique_index,
            )
        )

        # Add duplicate receipts for `room_id`.
        for _ in range(2):
            self.get_success(
                self.store.db_pool.simple_insert(
                    table,
                    {
                        "room_id": self.room_id,
                        "receipt_type": "m.read",
                        "user_id": self.user_id,
                        "thread_id": None,
                        "data": "{}",
                        **values,
                    },
                )
            )

        # Add a unique receipt for `other_room_id`.
        self.get_success(
            self.store.db_pool.simple_insert(
                table,
                {
                    "room_id": self.other_room_id,
                    "receipt_type": "m.read",
                    "user_id": self.user_id,
                    "thread_id": None,
                    "data": "{}",
                    **values,
                },
            )
        )

        # Insert and run the background update.
        self.get_success(
            self.store.db_pool.simple_insert(
                "background_updates",
                {
                    "update_name": update_name,
                    "progress_json": "{}",
                },
            )
        )

        self.store.db_pool.updates._all_done = False

        self.wait_for_background_updates()

        # Check that the background task deleted the duplicate receipts.
        res = self.get_success(
            self.store.db_pool.simple_select_onecol(
                table=table,
                keyvalues={
                    "room_id": self.room_id,
                    "receipt_type": "m.read",
                    "user_id": self.user_id,
                    # `simple_select_onecol` does not support NULL filters,
                    # so skip the filter on `thread_id`.
                },
                retcol="room_id",
                desc="get_receipt",
            )
        )
        self.assertEqual(0, len(res))

        # Check that the background task did not delete the unique receipts.
        res = self.get_success(
            self.store.db_pool.simple_select_onecol(
                table=table,
                keyvalues={
                    "room_id": self.other_room_id,
                    "receipt_type": "m.read",
                    "user_id": self.user_id,
                    # `simple_select_onecol` does not support NULL filters,
                    # so skip the filter on `thread_id`.
                },
                retcol="room_id",
                desc="get_receipt",
            )
        )
        self.assertEqual(1, len(res))

    def test_background_receipts_linearized_unique_index(self):
        """Test that the background update to uniqueify non-thread receipts in
        `receipts_linearized` works properly.
        """
        self._test_background_receipts_unique_index(
            "receipts_linearized_unique_index",
            "receipts_linearized_unique_index",
            "receipts_linearized",
            {
                "stream_id": 5,
                "event_id": "$some_event",
            },
        )

    def test_background_receipts_graph_unique_index(self):
        """Test that the background update to uniqueify non-thread receipts in
        `receipts_graph` works properly.
        """
        self._test_background_receipts_unique_index(
            "receipts_graph_unique_index",
            "receipts_graph_unique_index",
            "receipts_graph",
            {
                "event_ids": '["$some_event"]',
            },
        )
