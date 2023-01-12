# Copyright 2022 The Matrix.org Foundation C.I.C.
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
import json

from synapse.storage.engines import BaseDatabaseEngine, Sqlite3Engine
from synapse.storage.types import Cursor


def run_create(cur: Cursor, database_engine: BaseDatabaseEngine) -> None:
    """
    Upgrade the event_search table to use the porter tokenizer if it isn't already

    Applies only for sqlite.
    """
    if not isinstance(database_engine, Sqlite3Engine):
        return

    # Rebuild the table event_search table with tokenize=porter configured.
    cur.execute("DROP TABLE event_search")
    cur.execute(
        """
        CREATE VIRTUAL TABLE event_search
        USING fts4 (tokenize=porter, event_id, room_id, sender, key, value )
        """
    )

    # Re-run the background job to re-populate the event_search table.
    cur.execute("SELECT MIN(stream_ordering) FROM events")
    row = cur.fetchone()
    min_stream_id = row[0]

    # If there are not any events, nothing to do.
    if min_stream_id is None:
        return

    cur.execute("SELECT MAX(stream_ordering) FROM events")
    row = cur.fetchone()
    max_stream_id = row[0]

    progress = {
        "target_min_stream_id_inclusive": min_stream_id,
        "max_stream_id_exclusive": max_stream_id + 1,
    }
    progress_json = json.dumps(progress)

    sql = """
    INSERT into background_updates (ordering, update_name, progress_json)
    VALUES (?, ?, ?)
    """

    cur.execute(sql, (7310, "event_search", progress_json))
