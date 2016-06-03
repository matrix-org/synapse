# -*- coding: utf-8 -*-
# Copyright 2016 OpenMarket Ltd
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

from ._base import BaseSlavedStore
from ._slaved_id_tracker import SlavedIdTracker

from synapse.storage import DataStore
from synapse.storage.receipts import ReceiptsStore
from synapse.util.caches.stream_change_cache import StreamChangeCache

# So, um, we want to borrow a load of functions intended for reading from
# a DataStore, but we don't want to take functions that either write to the
# DataStore or are cached and don't have cache invalidation logic.
#
# Rather than write duplicate versions of those functions, or lift them to
# a common base class, we going to grab the underlying __func__ object from
# the method descriptor on the DataStore and chuck them into our class.


class SlavedReceiptsStore(BaseSlavedStore):

    def __init__(self, db_conn, hs):
        super(SlavedReceiptsStore, self).__init__(db_conn, hs)

        self._receipts_id_gen = SlavedIdTracker(
            db_conn, "receipts_linearized", "stream_id"
        )

        self._receipts_stream_cache = StreamChangeCache(
            "ReceiptsRoomChangeCache", self._receipts_id_gen.get_current_token()
        )

    get_receipts_for_user = ReceiptsStore.__dict__["get_receipts_for_user"]
    get_linearized_receipts_for_room = (
        ReceiptsStore.__dict__["get_linearized_receipts_for_room"]
    )
    _get_linearized_receipts_for_rooms = (
        ReceiptsStore.__dict__["_get_linearized_receipts_for_rooms"]
    )
    get_last_receipt_event_id_for_user = (
        ReceiptsStore.__dict__["get_last_receipt_event_id_for_user"]
    )

    get_max_receipt_stream_id = DataStore.get_max_receipt_stream_id.__func__
    get_all_updated_receipts = DataStore.get_all_updated_receipts.__func__

    get_linearized_receipts_for_rooms = (
        DataStore.get_linearized_receipts_for_rooms.__func__
    )

    def stream_positions(self):
        result = super(SlavedReceiptsStore, self).stream_positions()
        result["receipts"] = self._receipts_id_gen.get_current_token()
        return result

    def process_replication(self, result):
        stream = result.get("receipts")
        if stream:
            self._receipts_id_gen.advance(int(stream["position"]))
            for row in stream["rows"]:
                position, room_id, receipt_type, user_id = row[:4]
                self.invalidate_caches_for_receipt(room_id, receipt_type, user_id)
                self._receipts_stream_cache.entity_has_changed(room_id, position)

        return super(SlavedReceiptsStore, self).process_replication(result)

    def invalidate_caches_for_receipt(self, room_id, receipt_type, user_id):
        self.get_receipts_for_user.invalidate((user_id, receipt_type))
        self.get_linearized_receipts_for_room.invalidate_many((room_id,))
        self.get_last_receipt_event_id_for_user.invalidate(
            (user_id, room_id, receipt_type)
        )
