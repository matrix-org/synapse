# -*- coding: utf-8 -*-
# Copyright 2016 OpenMarket Ltd
# Copyright 2018 New Vector Ltd
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

from synapse.replication.tcp.streams import ReceiptsStream
from synapse.storage.database import DatabasePool
from synapse.storage.databases.main.receipts import ReceiptsWorkerStore

from ._base import BaseSlavedStore
from ._slaved_id_tracker import SlavedIdTracker


class SlavedReceiptsStore(ReceiptsWorkerStore, BaseSlavedStore):
    def __init__(self, database: DatabasePool, db_conn, hs):
        # We instantiate this first as the ReceiptsWorkerStore constructor
        # needs to be able to call get_max_receipt_stream_id
        self._receipts_id_gen = SlavedIdTracker(
            db_conn, "receipts_linearized", "stream_id"
        )

        super().__init__(database, db_conn, hs)

    def get_max_receipt_stream_id(self):
        return self._receipts_id_gen.get_current_token()

    def invalidate_caches_for_receipt(self, room_id, receipt_type, user_id):
        self.get_receipts_for_user.invalidate((user_id, receipt_type))
        self._get_linearized_receipts_for_room.invalidate_many((room_id,))
        self.get_last_receipt_event_id_for_user.invalidate(
            (user_id, room_id, receipt_type)
        )
        self._invalidate_get_users_with_receipts_in_room(room_id, receipt_type, user_id)
        self.get_receipts_for_room.invalidate((room_id, receipt_type))

    def process_replication_rows(self, stream_name, instance_name, token, rows):
        if stream_name == ReceiptsStream.NAME:
            self._receipts_id_gen.advance(instance_name, token)
            for row in rows:
                self.invalidate_caches_for_receipt(
                    row.room_id, row.receipt_type, row.user_id
                )
                self._receipts_stream_cache.entity_has_changed(row.room_id, token)

        return super().process_replication_rows(stream_name, instance_name, token, rows)
