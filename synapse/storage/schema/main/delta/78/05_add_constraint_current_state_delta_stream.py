# Copyright 2023 The Matrix.org Foundation C.I.C
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

from synapse.storage.database import LoggingTransaction
from synapse.storage.engines import BaseDatabaseEngine, Sqlite3Engine


def run_create(cur: LoggingTransaction, database_engine: BaseDatabaseEngine) -> None:
    if isinstance(database_engine, Sqlite3Engine):
        create_sql = """
         CREATE TABLE temp_current_state_delta_stream (
            stream_id bigint NOT NULL,
            room_id text NOT NULL,
            type text NOT NULL,
            state_key text NOT NULL,
            event_id text,
            prev_event_id text,
            instance_name text
            CHECK (event_id != prev_event_id)
        )
        """
        cur.execute(create_sql)

        copy_sql = """
            INSERT INTO temp_current_state_delta_stream SELECT * FROM current_state_delta_stream
        """
        cur.execute(copy_sql)

        drop_sql = """
            DROP TABLE current_state_delta_stream
        """
        cur.execute(drop_sql)

        alter_sql = """
            ALTER TABLE temp_current_state_delta_stream RENAME to current_state_delta_stream
        """
        cur.execute(alter_sql)

        idx_sql = """
            CREATE INDEX current_state_delta_stream_idx ON current_state_delta_stream(stream_id)
        """
        cur.execute(idx_sql)
    else:
        constraint_sql = """
            ALTER TABLE current_state_delta_stream ADD CONSTRAINT prev_event_id_and_event_id_not_equal
            CHECK (prev_event_id != event_id)
        """
        cur.execute(constraint_sql)
