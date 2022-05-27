# Copyright 2021 The Matrix.org Foundation C.I.C.
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
from synapse.storage.engines import Sqlite3Engine


def run_create(cur, database_engine, *args, **kwargs):
    # Upgrade the event_search table to use the porter tokenizer if it isn't already
    if isinstance(database_engine, Sqlite3Engine):
        cur.execute("SELECT sql FROM sqlite_master WHERE name='event_search'")
        sql = cur.fetchone()
        if sql is None:
            raise Exception("The event_search table doesn't exist")
        if "tokenize=porter" not in sql[0]:
            cur.execute("DROP TABLE event_search")
            cur.execute(
                """CREATE VIRTUAL TABLE event_search
                           USING fts4 (tokenize=porter, event_id, room_id, sender, key, value )"""
            )

            # Run a background job to re-populate the event_search table.
            cur.execute("SELECT MIN(stream_ordering) FROM events")
            rows = cur.fetchall()
            min_stream_id = rows[0][0]

            cur.execute("SELECT MAX(stream_ordering) FROM events")
            rows = cur.fetchall()
            max_stream_id = rows[0][0]

            if min_stream_id is not None and max_stream_id is not None:
                progress = {
                    "target_min_stream_id_inclusive": min_stream_id,
                    "max_stream_id_exclusive": max_stream_id + 1,
                    "rows_inserted": 0,
                }
                progress_json = json.dumps(progress)

                sql = (
                    "INSERT into background_updates (update_name, progress_json)"
                    " VALUES (?, ?)"
                )

                cur.execute(sql, ("event_search", progress_json))


def run_upgrade(cur, database_engine, *args, **kwargs):
    pass
