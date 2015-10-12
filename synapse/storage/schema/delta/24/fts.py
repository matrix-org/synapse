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

from synapse.storage import get_statements
from synapse.storage.engines import PostgresEngine

logger = logging.getLogger(__name__)


POSTGRES_SQL = """
CREATE TABLE event_search (
    event_id TEXT,
    room_id TEXT,
    key TEXT,
    vector tsvector
);

INSERT INTO event_search SELECT
    event_id, room_id, 'content.body',
    to_tsvector('english', json::json->'content'->>'body')
    FROM events NATURAL JOIN event_json WHERE type = 'm.room.message';

INSERT INTO event_search SELECT
    event_id, room_id, 'content.name',
    to_tsvector('english', json::json->'content'->>'name')
    FROM events NATURAL JOIN event_json WHERE type = 'm.room.name';

INSERT INTO event_search SELECT
    event_id, room_id, 'content.topic',
    to_tsvector('english', json::json->'content'->>'topic')
    FROM events NATURAL JOIN event_json WHERE type = 'm.room.topic';


CREATE INDEX event_search_fts_idx ON event_search USING gin(vector);
CREATE INDEX event_search_ev_idx ON event_search(event_id);
"""


def run_upgrade(cur, database_engine, *args, **kwargs):
    if not isinstance(database_engine, PostgresEngine):
        # We only support FTS for postgres currently.
        return

    for statement in get_statements(POSTGRES_SQL.splitlines()):
        cur.execute(statement)
