# -*- coding: utf-8 -*-
# Copyright 2020 The Matrix.org Foundation C.I.C.
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

from synapse.replication.tcp.streams._base import (
    _STREAM_UPDATE_TARGET_ROW_COUNT,
    AccountDataStream,
)

from tests.replication._base import BaseStreamTestCase


class AccountDataStreamTestCase(BaseStreamTestCase):
    def test_update_function_room_account_data_limit(self):
        """Test replication with many room account data updates
        """
        store = self.hs.get_datastore()

        # generate lots of account data updates
        updates = []
        for i in range(_STREAM_UPDATE_TARGET_ROW_COUNT + 5):
            update = "m.test_type.%i" % (i,)
            self.get_success(
                store.add_account_data_to_room("test_user", "test_room", update, {})
            )
            updates.append(update)

        # also one global update
        self.get_success(store.add_account_data_for_user("test_user", "m.global", {}))

        # tell the notifier to catch up to avoid duplicate rows.
        # workaround for https://github.com/matrix-org/synapse/issues/7360
        # FIXME remove this when the above is fixed
        self.replicate()

        # check we're testing what we think we are: no rows should yet have been
        # received
        self.assertEqual([], self.test_handler.received_rdata_rows)

        # now reconnect to pull the updates
        self.reconnect()
        self.replicate()

        # we should have received all the expected rows in the right order
        received_rows = self.test_handler.received_rdata_rows

        for t in updates:
            (stream_name, token, row) = received_rows.pop(0)
            self.assertEqual(stream_name, AccountDataStream.NAME)
            self.assertIsInstance(row, AccountDataStream.AccountDataStreamRow)
            self.assertEqual(row.data_type, t)
            self.assertEqual(row.room_id, "test_room")

        (stream_name, token, row) = received_rows.pop(0)
        self.assertIsInstance(row, AccountDataStream.AccountDataStreamRow)
        self.assertEqual(row.data_type, "m.global")
        self.assertIsNone(row.room_id)

        self.assertEqual([], received_rows)

    def test_update_function_global_account_data_limit(self):
        """Test replication with many global account data updates
        """
        store = self.hs.get_datastore()

        # generate lots of account data updates
        updates = []
        for i in range(_STREAM_UPDATE_TARGET_ROW_COUNT + 5):
            update = "m.test_type.%i" % (i,)
            self.get_success(store.add_account_data_for_user("test_user", update, {}))
            updates.append(update)

        # also one per-room update
        self.get_success(
            store.add_account_data_to_room("test_user", "test_room", "m.per_room", {})
        )

        # tell the notifier to catch up to avoid duplicate rows.
        # workaround for https://github.com/matrix-org/synapse/issues/7360
        # FIXME remove this when the above is fixed
        self.replicate()

        # check we're testing what we think we are: no rows should yet have been
        # received
        self.assertEqual([], self.test_handler.received_rdata_rows)

        # now reconnect to pull the updates
        self.reconnect()
        self.replicate()

        # we should have received all the expected rows in the right order
        received_rows = self.test_handler.received_rdata_rows

        for t in updates:
            (stream_name, token, row) = received_rows.pop(0)
            self.assertEqual(stream_name, AccountDataStream.NAME)
            self.assertIsInstance(row, AccountDataStream.AccountDataStreamRow)
            self.assertEqual(row.data_type, t)
            self.assertIsNone(row.room_id)

        (stream_name, token, row) = received_rows.pop(0)
        self.assertIsInstance(row, AccountDataStream.AccountDataStreamRow)
        self.assertEqual(row.data_type, "m.per_room")
        self.assertEqual(row.room_id, "test_room")

        self.assertEqual([], received_rows)
