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

from synapse.storage import DataStore
from synapse.util.caches.expiringcache import ExpiringCache
from synapse.util.caches.stream_change_cache import StreamChangeCache

from ._base import BaseSlavedStore
from ._slaved_id_tracker import SlavedIdTracker


class SlavedDeviceInboxStore(BaseSlavedStore):
    def __init__(self, db_conn, hs):
        super(SlavedDeviceInboxStore, self).__init__(db_conn, hs)
        self._device_inbox_id_gen = SlavedIdTracker(
            db_conn, "device_max_stream_id", "stream_id",
        )
        self._device_inbox_stream_cache = StreamChangeCache(
            "DeviceInboxStreamChangeCache",
            self._device_inbox_id_gen.get_current_token()
        )
        self._device_federation_outbox_stream_cache = StreamChangeCache(
            "DeviceFederationOutboxStreamChangeCache",
            self._device_inbox_id_gen.get_current_token()
        )

        self._last_device_delete_cache = ExpiringCache(
            cache_name="last_device_delete_cache",
            clock=self._clock,
            max_len=10000,
            expiry_ms=30 * 60 * 1000,
        )

    get_to_device_stream_token = DataStore.get_to_device_stream_token.__func__
    get_new_messages_for_device = DataStore.get_new_messages_for_device.__func__
    get_new_device_msgs_for_remote = DataStore.get_new_device_msgs_for_remote.__func__
    delete_messages_for_device = DataStore.delete_messages_for_device.__func__
    delete_device_msgs_for_remote = DataStore.delete_device_msgs_for_remote.__func__

    def stream_positions(self):
        result = super(SlavedDeviceInboxStore, self).stream_positions()
        result["to_device"] = self._device_inbox_id_gen.get_current_token()
        return result

    def process_replication_rows(self, stream_name, token, rows):
        if stream_name == "to_device":
            self._device_inbox_id_gen.advance(token)
            for row in rows:
                if row.entity.startswith("@"):
                    self._device_inbox_stream_cache.entity_has_changed(
                        row.entity, token
                    )
                else:
                    self._device_federation_outbox_stream_cache.entity_has_changed(
                        row.entity, token
                    )
        return super(SlavedDeviceInboxStore, self).process_replication_rows(
            stream_name, token, rows
        )
