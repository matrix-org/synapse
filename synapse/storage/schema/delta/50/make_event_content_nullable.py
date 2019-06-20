# -*- coding: utf-8 -*-
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

"""
We want to stop populating 'event.content', so we need to make it nullable.

If this has to be rolled back, then the following should populate the missing data:

Postgres:

    UPDATE events SET content=(ej.json::json)->'content' FROM event_json ej
    WHERE ej.event_id = events.event_id AND
        stream_ordering < (
            SELECT stream_ordering FROM events WHERE content IS NOT NULL
            ORDER BY stream_ordering LIMIT 1
        );

    UPDATE events SET content=(ej.json::json)->'content' FROM event_json ej
    WHERE ej.event_id = events.event_id AND
        stream_ordering > (
            SELECT stream_ordering FROM events WHERE content IS NOT NULL
            ORDER BY stream_ordering DESC LIMIT 1
        );

SQLite:

    UPDATE events SET content=(
        SELECT json_extract(json,'$.content') FROM event_json ej
        WHERE ej.event_id = events.event_id
    )
    WHERE
        stream_ordering < (
            SELECT stream_ordering FROM events WHERE content IS NOT NULL
            ORDER BY stream_ordering LIMIT 1
        )
        OR stream_ordering > (
            SELECT stream_ordering FROM events WHERE content IS NOT NULL
            ORDER BY stream_ordering DESC LIMIT 1
        );

"""

import logging

from synapse.storage.engines import PostgresEngine

logger = logging.getLogger(__name__)


def run_create(cur, database_engine, *args, **kwargs):
    pass


def run_upgrade(cur, database_engine, *args, **kwargs):
    if isinstance(database_engine, PostgresEngine):
        cur.execute("""
            ALTER TABLE events ALTER COLUMN content DROP NOT NULL;
        """)
        return

    # sqlite is an arse about this. ref: https://www.sqlite.org/lang_altertable.html

    cur.execute("SELECT sql FROM sqlite_master WHERE tbl_name='events' AND type='table'")
    (oldsql,) = cur.fetchone()

    sql = oldsql.replace("content TEXT NOT NULL", "content TEXT")
    if sql == oldsql:
        raise Exception("Couldn't find null constraint to drop in %s" % oldsql)

    logger.info("Replacing definition of 'events' with: %s", sql)

    cur.execute("PRAGMA schema_version")
    (oldver,) = cur.fetchone()
    cur.execute("PRAGMA writable_schema=ON")
    cur.execute(
        "UPDATE sqlite_master SET sql=? WHERE tbl_name='events' AND type='table'",
        (sql, ),
    )
    cur.execute("PRAGMA schema_version=%i" % (oldver + 1,))
    cur.execute("PRAGMA writable_schema=OFF")
