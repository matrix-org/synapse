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

from typing import TYPE_CHECKING, Any, Iterable

from synapse.replication.slave.storage._slaved_id_tracker import SlavedIdTracker
from synapse.replication.tcp.streams._base import DeviceListsStream, UserSignatureStream
from synapse.storage.database import DatabasePool, LoggingDatabaseConnection
from synapse.storage.databases.main.devices import DeviceWorkerStore

if TYPE_CHECKING:
    from synapse.server import HomeServer


class SlavedDeviceStore(DeviceWorkerStore):
    def __init__(
        self,
        database: DatabasePool,
        db_conn: LoggingDatabaseConnection,
        hs: "HomeServer",
    ):
        self.hs = hs

        self._device_list_id_gen = SlavedIdTracker(
            db_conn,
            "device_lists_stream",
            "stream_id",
            extra_tables=[
                ("user_signature_stream", "stream_id"),
                ("device_lists_outbound_pokes", "stream_id"),
                ("device_lists_changes_in_room", "stream_id"),
            ],
        )

        super().__init__(database, db_conn, hs)

    def get_device_stream_token(self) -> int:
        return self._device_list_id_gen.get_current_token()

    def process_replication_rows(
        self, stream_name: str, instance_name: str, token: int, rows: Iterable[Any]
    ) -> None:
        if stream_name == DeviceListsStream.NAME:
            self._device_list_id_gen.advance(instance_name, token)
            self._invalidate_caches_for_devices(token, rows)
        elif stream_name == UserSignatureStream.NAME:
            self._device_list_id_gen.advance(instance_name, token)
            for row in rows:
                self._user_signature_stream_cache.entity_has_changed(row.user_id, token)
        return super().process_replication_rows(stream_name, instance_name, token, rows)

    def _invalidate_caches_for_devices(
        self, token: int, rows: Iterable[DeviceListsStream.DeviceListsStreamRow]
    ) -> None:
        for row in rows:
            # The entities are either user IDs (starting with '@') whose devices
            # have changed, or remote servers that we need to tell about
            # changes.
            if row.entity.startswith("@"):
                self._device_list_stream_cache.entity_has_changed(row.entity, token)
                self.get_cached_devices_for_user.invalidate((row.entity,))
                self._get_cached_user_device.invalidate((row.entity,))
                self.get_device_list_last_stream_id_for_remote.invalidate((row.entity,))

            else:
                self._device_list_federation_stream_cache.entity_has_changed(
                    row.entity, token
                )
