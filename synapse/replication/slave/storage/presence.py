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

from synapse.replication.tcp.streams import PresenceStream
from synapse.storage import DataStore
from synapse.storage.database import DatabasePool
from synapse.storage.databases.main.presence import PresenceStore
from synapse.util.caches.stream_change_cache import StreamChangeCache

from ._base import BaseSlavedStore
from ._slaved_id_tracker import SlavedIdTracker


class SlavedPresenceStore(BaseSlavedStore):
    def __init__(self, database: DatabasePool, db_conn, hs):
        super().__init__(database, db_conn, hs)
        self._presence_id_gen = SlavedIdTracker(db_conn, "presence_stream", "stream_id")

        self._presence_on_startup = self._get_active_presence(db_conn)  # type: ignore

        self.presence_stream_cache = StreamChangeCache(
            "PresenceStreamChangeCache", self._presence_id_gen.get_current_token()
        )

    _get_active_presence = DataStore._get_active_presence
    take_presence_startup_info = DataStore.take_presence_startup_info
    _get_presence_for_user = PresenceStore.__dict__["_get_presence_for_user"]
    get_presence_for_users = PresenceStore.__dict__["get_presence_for_users"]

    def get_current_presence_token(self):
        return self._presence_id_gen.get_current_token()

    def process_replication_rows(self, stream_name, instance_name, token, rows):
        if stream_name == PresenceStream.NAME:
            self._presence_id_gen.advance(instance_name, token)
            for row in rows:
                self.presence_stream_cache.entity_has_changed(row.user_id, token)
                self._get_presence_for_user.invalidate((row.user_id,))
        return super().process_replication_rows(stream_name, instance_name, token, rows)
