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
from synapse.util.caches.stream_change_cache import StreamChangeCache

from ._base import BaseSlavedStore, __func__
from ._slaved_id_tracker import SlavedIdTracker


class SlavedGroupServerStore(BaseSlavedStore):
    def __init__(self, db_conn, hs):
        super(SlavedGroupServerStore, self).__init__(db_conn, hs)

        self.hs = hs

        self._group_updates_id_gen = SlavedIdTracker(
            db_conn, "local_group_updates", "stream_id"
        )
        self._group_updates_stream_cache = StreamChangeCache(
            "_group_updates_stream_cache",
            self._group_updates_id_gen.get_current_token(),
        )

    get_groups_changes_for_user = __func__(DataStore.get_groups_changes_for_user)
    get_group_stream_token = __func__(DataStore.get_group_stream_token)
    get_all_groups_for_user = __func__(DataStore.get_all_groups_for_user)

    def stream_positions(self):
        result = super(SlavedGroupServerStore, self).stream_positions()
        result["groups"] = self._group_updates_id_gen.get_current_token()
        return result

    def process_replication_rows(self, stream_name, token, rows):
        if stream_name == "groups":
            self._group_updates_id_gen.advance(token)
            for row in rows:
                self._group_updates_stream_cache.entity_has_changed(row.user_id, token)

        return super(SlavedGroupServerStore, self).process_replication_rows(
            stream_name, token, rows
        )
