# -*- coding: utf-8 -*-
# Copyright 2016 OpenMarket Ltd
# Copyright 2018 New Vector Ltd
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
from synapse.replication.tcp.streams import AccountDataStream, TagAccountDataStream
from synapse.storage.database import DatabasePool
from synapse.storage.databases.main.account_data import AccountDataWorkerStore
from synapse.storage.databases.main.tags import TagsWorkerStore


class SlavedAccountDataStore(TagsWorkerStore, AccountDataWorkerStore, BaseSlavedStore):
    def __init__(self, database: DatabasePool, db_conn, hs):
        self._account_data_id_gen = SlavedIdTracker(
            db_conn,
            "account_data",
            "stream_id",
            extra_tables=[
                ("room_account_data", "stream_id"),
                ("room_tags_revisions", "stream_id"),
            ],
        )

        super().__init__(database, db_conn, hs)

    def get_max_account_data_stream_id(self):
        return self._account_data_id_gen.get_current_token()

    def process_replication_rows(self, stream_name, instance_name, token, rows):
        if stream_name == TagAccountDataStream.NAME:
            self._account_data_id_gen.advance(instance_name, token)
            for row in rows:
                self.get_tags_for_user.invalidate((row.user_id,))
                self._account_data_stream_cache.entity_has_changed(row.user_id, token)
        elif stream_name == AccountDataStream.NAME:
            self._account_data_id_gen.advance(instance_name, token)
            for row in rows:
                if not row.room_id:
                    self.get_global_account_data_by_type_for_user.invalidate(
                        (row.data_type, row.user_id)
                    )
                self.get_account_data_for_user.invalidate((row.user_id,))
                self.get_account_data_for_room.invalidate((row.user_id, row.room_id))
                self.get_account_data_for_room_and_type.invalidate(
                    (row.user_id, row.room_id, row.data_type)
                )
                self._account_data_stream_cache.entity_has_changed(row.user_id, token)
        return super().process_replication_rows(stream_name, instance_name, token, rows)
