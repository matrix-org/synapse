# Copyright 2017 Vector Creations Ltd
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

import logging

from synapse.storage.prepare_database import get_statements
from synapse.storage.engines import PostgresEngine, Sqlite3Engine

logger = logging.getLogger(__name__)


BOTH_TABLES = """
CREATE TABLE user_directory_stream_pos (
    Lock CHAR(1) NOT NULL DEFAULT 'X' UNIQUE,  -- Makes sure this table only has one row.
    stream_id BIGINT,
    CHECK (Lock='X')
);

INSERT INTO user_directory_stream_pos (stream_id) VALUES (null);
"""


POSTGRES_TABLE = """
CREATE TABLE user_directory (
    user_id TEXT NOT NULL,
    room_id TEXT NOT NULL,
    display_name TEXT,
    avatar_url TEXT,
    vector tsvector
);

CREATE INDEX user_directory_fts_idx ON user_directory USING gin(vector);
CREATE INDEX user_directory_user_idx ON user_directory(user_id);
"""


SQLITE_TABLE = """
CREATE VIRTUAL TABLE user_directory
    USING fts4 ( user_id, room_id, display_name, avatar_url, value );
"""


def run_create(cur, database_engine, *args, **kwargs):
    for statement in get_statements(BOTH_TABLES.splitlines()):
        cur.execute(statement)

    if isinstance(database_engine, PostgresEngine):
        for statement in get_statements(POSTGRES_TABLE.splitlines()):
            cur.execute(statement)
    elif isinstance(database_engine, Sqlite3Engine):
        for statement in get_statements(SQLITE_TABLE.splitlines()):
            cur.execute(statement)
    else:
        raise Exception("Unrecognized database engine")


def run_upgrade(*args, **kwargs):
    pass
