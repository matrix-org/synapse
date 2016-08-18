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

from synapse.storage.prepare_database import get_statements
from synapse.storage.engines import PostgresEngine

import logging

logger = logging.getLogger(__name__)


# This stream is used to notify replication slaves that some caches have
# been invalidated that they cannot infer from the other streams.
CREATE_TABLE = """
CREATE TABLE cache_invalidation_stream (
    stream_id       BIGINT,
    cache_func      TEXT,
    keys            TEXT[],
    invalidation_ts BIGINT
);

CREATE INDEX cache_invalidation_stream_id ON cache_invalidation_stream(stream_id);
"""


def run_create(cur, database_engine, *args, **kwargs):
    if not isinstance(database_engine, PostgresEngine):
        return

    for statement in get_statements(CREATE_TABLE.splitlines()):
        cur.execute(statement)


def run_upgrade(cur, database_engine, *args, **kwargs):
    pass
