# Copyright 2015 OpenMarket Ltd
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

import ujson

logger = logging.getLogger(__name__)


POSTGRES_SQL = """
CREATE TABLE IF NOT EXISTS event_search (
    event_id TEXT,
    room_id TEXT,
    sender TEXT,
    key TEXT,
    vector tsvector
);

INSERT INTO event_search SELECT
    event_id, room_id, json::json->>'sender', 'content.body',
    to_tsvector('english', json::json->'content'->>'body')
    FROM events NATURAL JOIN event_json WHERE type = 'm.room.message';

INSERT INTO event_search SELECT
    event_id, room_id, json::json->>'sender', 'content.name',
    to_tsvector('english', json::json->'content'->>'name')
    FROM events NATURAL JOIN event_json WHERE type = 'm.room.name';

INSERT INTO event_search SELECT
    event_id, room_id, json::json->>'sender', 'content.topic',
    to_tsvector('english', json::json->'content'->>'topic')
    FROM events NATURAL JOIN event_json WHERE type = 'm.room.topic';


CREATE INDEX event_search_fts_idx ON event_search USING gin(vector);
CREATE INDEX event_search_ev_idx ON event_search(event_id);
CREATE INDEX event_search_ev_ridx ON event_search(room_id);
"""


SQLITE_TABLE = (
    "CREATE VIRTUAL TABLE IF NOT EXISTS event_search"
    " USING fts4 ( event_id, room_id, sender, key, value )"
)


def run_upgrade(cur, database_engine, *args, **kwargs):
    if isinstance(database_engine, PostgresEngine):
        run_postgres_upgrade(cur)
        return

    if isinstance(database_engine, Sqlite3Engine):
        run_sqlite_upgrade(cur)
        return


def run_postgres_upgrade(cur):
    for statement in get_statements(POSTGRES_SQL.splitlines()):
        cur.execute(statement)


def run_sqlite_upgrade(cur):
        cur.execute(SQLITE_TABLE)

        rowid = -1
        while True:
            cur.execute(
                "SELECT rowid, json FROM event_json"
                " WHERE rowid > ?"
                " ORDER BY rowid ASC LIMIT 100",
                (rowid,)
            )

            res = cur.fetchall()

            if not res:
                break

            events = [
                ujson.loads(js)
                for _, js in res
            ]

            rowid = max(rid for rid, _ in res)

            rows = []
            for ev in events:
                content = ev.get("content", {})
                body = content.get("body", None)
                name = content.get("name", None)
                topic = content.get("topic", None)
                sender = ev.get("sender", None)
                if ev["type"] == "m.room.message" and body:
                    rows.append((
                        ev["event_id"], ev["room_id"], sender, "content.body", body
                    ))
                if ev["type"] == "m.room.name" and name:
                    rows.append((
                        ev["event_id"], ev["room_id"], sender, "content.name", name
                    ))
                if ev["type"] == "m.room.topic" and topic:
                    rows.append((
                        ev["event_id"], ev["room_id"], sender, "content.topic", topic
                    ))

            if rows:
                logger.info(rows)
                cur.executemany(
                    "INSERT INTO event_search (event_id, room_id, sender, key, value)"
                    " VALUES (?,?,?,?,?)",
                    rows
                )
