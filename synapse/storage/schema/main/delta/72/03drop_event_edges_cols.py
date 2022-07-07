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


from synapse.storage.engines import BaseDatabaseEngine, PostgresEngine, Sqlite3Engine
from synapse.storage.types import Cursor

# event_edges.room_id and event_edges.is_state are no longer used, so we can drop them.


def run_create(cur: Cursor, database_engine: BaseDatabaseEngine, *args, **kwargs):
    if isinstance(database_engine, PostgresEngine):
        _update_postgres(cur)
    elif isinstance(database_engine, Sqlite3Engine):
        _update_sqlite(cur)
    else:
        raise NotImplementedError("Unknown database engine")


def _update_postgres(cur: Cursor):
    # for postgres, we have to wait for the background update which drops bad rows to
    # complete before we can actually drop the bad columns.
    cur.execute(
        """
        INSERT INTO background_updates (ordering, update_name, progress_json, depends_on)
            VALUES
            (7203, 'event_edges_drop_old_cols', '{}', 'event_edges_drop_invalid_rows')
        """
    )


def _update_sqlite(cur: Cursor):
    # sqlite is easier in one way, in that there was no background update to worry
    # about. However, there is no ALTER TABLE DROP COLUMN (at least until 3.33), so it'a
    # rather more fiddly.
    #
    # However, we recently (in 71/01rebuild_event_edges.sql.sqlite) rebuilt event_edges,
    # so we know that room_id and is_state are the last columns in the schema, which
    # means that we can just tell sqlite to change the schema without needing to change
    # the data.
    sql = (
        'CREATE TABLE "event_edges" (event_id TEXT NOT NULL, '
        "prev_event_id TEXT NOT NULL, "
        "FOREIGN KEY(event_id) REFERENCES events(event_id))"
    )

    cur.execute("PRAGMA schema_version")
    (oldver,) = cur.fetchone()
    cur.execute("PRAGMA writable_schema=ON")
    cur.execute(
        "UPDATE sqlite_master SET sql=? WHERE tbl_name='event_edges' AND type='table'",
        (sql,),
    )
    cur.execute("PRAGMA schema_version=%i" % (oldver + 1,))
    cur.execute("PRAGMA writable_schema=OFF")
