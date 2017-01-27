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
from synapse.util.caches.stream_change_cache import StreamChangeCache


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

    get_device_stream_token = DataStore.get_device_stream_token.__func__
    get_user_whose_devices_changed = DataStore.get_user_whose_devices_changed.__func__
    get_devices_by_remote = DataStore.get_devices_by_remote.__func__
    _get_devices_by_remote_txn = DataStore._get_devices_by_remote_txn.__func__
    _get_e2e_device_keys_txn = DataStore._get_e2e_device_keys_txn.__func__
    mark_as_sent_devices_by_remote = DataStore.mark_as_sent_devices_by_remote.__func__
    _mark_as_sent_devices_by_remote_txn = (
        DataStore._mark_as_sent_devices_by_remote_txn.__func__
    )

    def stream_positions(self):
        result = super(SlavedDeviceStore, self).stream_positions()
        result["device_lists"] = self._device_list_id_gen.get_current_token()
        return result

    def process_replication(self, result):
        stream = result.get("device_lists")
        if stream:
            self._device_list_id_gen.advance(int(stream["position"]))
            for row in stream["rows"]:
                stream_id = row[0]
                user_id = row[1]
                destination = row[2]

                self._device_list_stream_cache.entity_has_changed(
                    user_id, stream_id
                )

                if destination:
                    self._device_list_federation_stream_cache.entity_has_changed(
                        destination, stream_id
                    )

        return super(SlavedDeviceStore, self).process_replication(result)
