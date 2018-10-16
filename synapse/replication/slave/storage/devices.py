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
from synapse.storage.end_to_end_keys import EndToEndKeyStore
from synapse.util.caches.stream_change_cache import StreamChangeCache

from ._base import BaseSlavedStore, __func__
from ._slaved_id_tracker import SlavedIdTracker


class SlavedDeviceStore(BaseSlavedStore):
    def __init__(self, db_conn, hs):
        super(SlavedDeviceStore, self).__init__(db_conn, hs)

        self.hs = hs

        self._device_list_id_gen = SlavedIdTracker(
            db_conn, "device_lists_stream", "stream_id",
        )
        device_list_max = self._device_list_id_gen.get_current_token()
        self._device_list_stream_cache = StreamChangeCache(
            "DeviceListStreamChangeCache", device_list_max,
        )
        self._device_list_federation_stream_cache = StreamChangeCache(
            "DeviceListFederationStreamChangeCache", device_list_max,
        )

    get_device_stream_token = __func__(DataStore.get_device_stream_token)
    get_user_whose_devices_changed = __func__(DataStore.get_user_whose_devices_changed)
    get_devices_by_remote = __func__(DataStore.get_devices_by_remote)
    _get_devices_by_remote_txn = __func__(DataStore._get_devices_by_remote_txn)
    _get_e2e_device_keys_txn = __func__(DataStore._get_e2e_device_keys_txn)
    mark_as_sent_devices_by_remote = __func__(DataStore.mark_as_sent_devices_by_remote)
    _mark_as_sent_devices_by_remote_txn = (
        __func__(DataStore._mark_as_sent_devices_by_remote_txn)
    )
    count_e2e_one_time_keys = EndToEndKeyStore.__dict__["count_e2e_one_time_keys"]

    def stream_positions(self):
        result = super(SlavedDeviceStore, self).stream_positions()
        result["device_lists"] = self._device_list_id_gen.get_current_token()
        return result

    def process_replication_rows(self, stream_name, token, rows):
        if stream_name == "device_lists":
            self._device_list_id_gen.advance(token)
            for row in rows:
                self._device_list_stream_cache.entity_has_changed(
                    row.user_id, token
                )

                if row.destination:
                    self._device_list_federation_stream_cache.entity_has_changed(
                        row.destination, token
                    )
        return super(SlavedDeviceStore, self).process_replication_rows(
            stream_name, token, rows
        )
