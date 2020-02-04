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

from synapse.replication.slave.storage._base import BaseSlavedStore
from synapse.replication.slave.storage._slaved_id_tracker import SlavedIdTracker
from synapse.replication.tcp.streams._base import DeviceListsStream, UserSignatureStream
from synapse.storage.data_stores.main.devices import DeviceWorkerStore
from synapse.storage.data_stores.main.end_to_end_keys import EndToEndKeyWorkerStore
from synapse.storage.database import Database
from synapse.util.caches.stream_change_cache import StreamChangeCache


class SlavedDeviceStore(EndToEndKeyWorkerStore, DeviceWorkerStore, BaseSlavedStore):
    def __init__(self, database: Database, db_conn, hs):
        super(SlavedDeviceStore, self).__init__(database, db_conn, hs)

        self.hs = hs

        self._device_list_id_gen = SlavedIdTracker(
            db_conn, "device_lists_stream", "stream_id"
        )
        device_list_max = self._device_list_id_gen.get_current_token()
        self._device_list_stream_cache = StreamChangeCache(
            "DeviceListStreamChangeCache", device_list_max
        )
        self._user_signature_stream_cache = StreamChangeCache(
            "UserSignatureStreamChangeCache", device_list_max
        )
        self._device_list_federation_stream_cache = StreamChangeCache(
            "DeviceListFederationStreamChangeCache", device_list_max
        )

    def stream_positions(self):
        result = super(SlavedDeviceStore, self).stream_positions()
        # The user signature stream uses the same stream ID generator as the
        # device list stream, so set them both to the device list ID
        # generator's current token.
        current_token = self._device_list_id_gen.get_current_token()
        result[DeviceListsStream.NAME] = current_token
        result[UserSignatureStream.NAME] = current_token
        return result

    def process_replication_rows(self, stream_name, token, rows):
        if stream_name == DeviceListsStream.NAME:
            self._device_list_id_gen.advance(token)
            for row in rows:
                self._invalidate_caches_for_devices(token, row.user_id, row.destination)
        elif stream_name == UserSignatureStream.NAME:
            for row in rows:
                self._user_signature_stream_cache.entity_has_changed(row.user_id, token)
        return super(SlavedDeviceStore, self).process_replication_rows(
            stream_name, token, rows
        )

    def _invalidate_caches_for_devices(self, token, user_id, destination):
        self._device_list_stream_cache.entity_has_changed(user_id, token)

        if destination:
            self._device_list_federation_stream_cache.entity_has_changed(
                destination, token
            )

        self.get_cached_devices_for_user.invalidate((user_id,))
        self._get_cached_user_device.invalidate_many((user_id,))
        self.get_device_list_last_stream_id_for_remote.invalidate((user_id,))
