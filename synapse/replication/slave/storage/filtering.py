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

from typing import TYPE_CHECKING

from synapse.storage._base import SQLBaseStore
from synapse.storage.database import DatabasePool, LoggingDatabaseConnection
from synapse.storage.databases.main.filtering import FilteringStore

if TYPE_CHECKING:
    from synapse.server import HomeServer


class SlavedFilteringStore(SQLBaseStore):
    def __init__(
        self,
        database: DatabasePool,
        db_conn: LoggingDatabaseConnection,
        hs: "HomeServer",
    ):
        super().__init__(database, db_conn, hs)

    # Filters are immutable so this cache doesn't need to be expired
    get_user_filter = FilteringStore.__dict__["get_user_filter"]
