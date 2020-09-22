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
from synapse.replication.tcp.streams import GroupServerStream
from synapse.storage.database import DatabasePool
from synapse.storage.databases.main.group_server import GroupServerWorkerStore
from synapse.util.caches.stream_change_cache import StreamChangeCache


class SlavedGroupServerStore(GroupServerWorkerStore, BaseSlavedStore):
    def __init__(self, database: DatabasePool, db_conn, hs):
        super().__init__(database, db_conn, hs)

        self.hs = hs

        self._group_updates_id_gen = SlavedIdTracker(
            db_conn, "local_group_updates", "stream_id"
        )
        self._group_updates_stream_cache = StreamChangeCache(
            "_group_updates_stream_cache",
            self._group_updates_id_gen.get_current_token(),
        )

    def get_group_stream_token(self):
        return self._group_updates_id_gen.get_current_token()

    def process_replication_rows(self, stream_name, instance_name, token, rows):
        if stream_name == GroupServerStream.NAME:
            self._group_updates_id_gen.advance(instance_name, token)
            for row in rows:
                self._group_updates_stream_cache.entity_has_changed(row.user_id, token)

        return super().process_replication_rows(stream_name, instance_name, token, rows)
