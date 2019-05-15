# -*- coding: utf-8 -*-
# Copyright 2019 New Vector Ltd
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
from synapse.replication.tcp.streams._base import ReceiptsStreamRow

from tests.replication.tcp.streams._base import BaseStreamTestCase

USER_ID = "@feeling:blue"
ROOM_ID = "!room:blue"
EVENT_ID = "$event:blue"


class ReceiptsStreamTestCase(BaseStreamTestCase):
    def test_receipt(self):
        # make the client subscribe to the receipts stream
        self.replicate_stream("receipts", "NOW")

        # tell the master to send a new receipt
        self.get_success(
            self.hs.get_datastore().insert_receipt(
                ROOM_ID, "m.read", USER_ID, [EVENT_ID], {"a": 1}
            )
        )
        self.replicate()

        # there should be one RDATA command
        rdata_rows = self.test_handler.received_rdata_rows
        self.assertEqual(1, len(rdata_rows))
        self.assertEqual(rdata_rows[0][0], "receipts")
        row = rdata_rows[0][2]  # type: ReceiptsStreamRow
        self.assertEqual(ROOM_ID, row.room_id)
        self.assertEqual("m.read", row.receipt_type)
        self.assertEqual(USER_ID, row.user_id)
        self.assertEqual(EVENT_ID, row.event_id)
        self.assertEqual({"a": 1}, row.data)
