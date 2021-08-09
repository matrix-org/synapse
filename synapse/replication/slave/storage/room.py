# Copyright 2015, 2016 OpenMarket Ltd
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

from synapse.storage.database import DatabasePool
from synapse.storage.databases.main.room import RoomWorkerStore

from ._base import BaseSlavedStore


class RoomStore(RoomWorkerStore, BaseSlavedStore):
    def __init__(self, database: DatabasePool, db_conn, hs):
        super().__init__(database, db_conn, hs)

    def process_replication_rows(self, stream_name, instance_name, token, rows):
        return super().process_replication_rows(stream_name, instance_name, token, rows)
