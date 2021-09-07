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

import logging

from synapse.storage.engines import PostgresEngine
from synapse.storage.prepare_database import get_statements

logger = logging.getLogger(__name__)

DROP_INDICES = """
-- We only ever query based on event_id
DROP INDEX IF EXISTS state_events_room_id;
DROP INDEX IF EXISTS state_events_type;
DROP INDEX IF EXISTS state_events_state_key;

-- room_id is indexed elsewhere
DROP INDEX IF EXISTS current_state_events_room_id;
DROP INDEX IF EXISTS current_state_events_state_key;
DROP INDEX IF EXISTS current_state_events_type;

DROP INDEX IF EXISTS transactions_have_ref;

-- (topological_ordering, stream_ordering, room_id) seems like a strange index,
-- and is used incredibly rarely.
DROP INDEX IF EXISTS events_order_topo_stream_room;

-- an equivalent index to this actually gets re-created in delta 41, because it
-- turned out that deleting it wasn't a great plan :/. In any case, let's
-- delete it here, and delta 41 will create a new one with an added UNIQUE
-- constraint
DROP INDEX IF EXISTS event_search_ev_idx;
"""

POSTGRES_DROP_CONSTRAINT = """
ALTER TABLE event_auth DROP CONSTRAINT IF EXISTS event_auth_event_id_auth_id_room_id_key;
"""

SQLITE_DROP_CONSTRAINT = """
DROP INDEX IF EXISTS evauth_edges_id;

CREATE TABLE IF NOT EXISTS event_auth_new(
    event_id TEXT NOT NULL,
    auth_id TEXT NOT NULL,
    room_id TEXT NOT NULL
);

INSERT INTO event_auth_new
    SELECT event_id, auth_id, room_id
    FROM event_auth;

DROP TABLE event_auth;

ALTER TABLE event_auth_new RENAME TO event_auth;

CREATE INDEX evauth_edges_id ON event_auth(event_id);
"""


def run_create(cur, database_engine, *args, **kwargs):
    for statement in get_statements(DROP_INDICES.splitlines()):
        cur.execute(statement)

    if isinstance(database_engine, PostgresEngine):
        drop_constraint = POSTGRES_DROP_CONSTRAINT
    else:
        drop_constraint = SQLITE_DROP_CONSTRAINT

    for statement in get_statements(drop_constraint.splitlines()):
        cur.execute(statement)


def run_upgrade(cur, database_engine, *args, **kwargs):
    pass
