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
from synapse.storage.presence import PresenceStore
from synapse.util.caches.stream_change_cache import StreamChangeCache

from ._base import BaseSlavedStore, __func__
from ._slaved_id_tracker import SlavedIdTracker


class SlavedPresenceStore(BaseSlavedStore):
    def __init__(self, db_conn, hs):
        super(SlavedPresenceStore, self).__init__(db_conn, hs)
        self._presence_id_gen = SlavedIdTracker(db_conn, "presence_stream", "stream_id")

        self._presence_on_startup = self._get_active_presence(db_conn)

        self.presence_stream_cache = self.presence_stream_cache = StreamChangeCache(
            "PresenceStreamChangeCache", self._presence_id_gen.get_current_token()
        )

    _get_active_presence = __func__(DataStore._get_active_presence)
    take_presence_startup_info = __func__(DataStore.take_presence_startup_info)
    _get_presence_for_user = PresenceStore.__dict__["_get_presence_for_user"]
    get_presence_for_users = PresenceStore.__dict__["get_presence_for_users"]

    def get_current_presence_token(self):
        return self._presence_id_gen.get_current_token()

    def stream_positions(self):
        result = super(SlavedPresenceStore, self).stream_positions()

        if self.hs.config.use_presence:
            position = self._presence_id_gen.get_current_token()
            result["presence"] = position

        return result

    def process_replication_rows(self, stream_name, token, rows):
        if stream_name == "presence":
            self._presence_id_gen.advance(token)
            for row in rows:
                self.presence_stream_cache.entity_has_changed(row.user_id, token)
                self._get_presence_for_user.invalidate((row.user_id,))
        return super(SlavedPresenceStore, self).process_replication_rows(
            stream_name, token, rows
        )
