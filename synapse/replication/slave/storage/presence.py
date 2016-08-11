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

from synapse.util.caches.stream_change_cache import StreamChangeCache
from synapse.storage import DataStore


class SlavedPresenceStore(BaseSlavedStore):
    def __init__(self, db_conn, hs):
        super(SlavedPresenceStore, self).__init__(db_conn, hs)
        self._presence_id_gen = SlavedIdTracker(
            db_conn, "presence_stream", "stream_id",
        )

        self._presence_on_startup = self._get_active_presence(db_conn)

        self.presence_stream_cache = self.presence_stream_cache = StreamChangeCache(
            "PresenceStreamChangeCache", self._presence_id_gen.get_current_token()
        )

    _get_active_presence = DataStore._get_active_presence.__func__
    take_presence_startup_info = DataStore.take_presence_startup_info.__func__
    get_presence_for_users = DataStore.get_presence_for_users.__func__

    def get_current_presence_token(self):
        return self._presence_id_gen.get_current_token()

    def stream_positions(self):
        result = super(SlavedPresenceStore, self).stream_positions()
        position = self._presence_id_gen.get_current_token()
        result["presence"] = position
        return result

    def process_replication(self, result):
        stream = result.get("presence")
        if stream:
            self._presence_id_gen.advance(int(stream["position"]))
            for row in stream["rows"]:
                position, user_id = row[:2]
                self.presence_stream_cache.entity_has_changed(
                    user_id, position
                )

        return super(SlavedPresenceStore, self).process_replication(result)
