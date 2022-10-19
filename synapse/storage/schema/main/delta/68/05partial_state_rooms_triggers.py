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


"""
This migration adds triggers to the partial_state_events tables to enforce uniqueness

Triggers cannot be expressed in .sql files, so we have to use a separate file.
"""
from synapse.storage.engines import BaseDatabaseEngine, PostgresEngine, Sqlite3Engine
from synapse.storage.types import Cursor


def run_create(cur: Cursor, database_engine: BaseDatabaseEngine, *args, **kwargs):
    # complain if the room_id in partial_state_events doesn't match
    # that in `events`. We already have a fk constraint which ensures that the event
    # exists in `events`, so all we have to do is raise if there is a row with a
    # matching stream_ordering but not a matching room_id.
    if isinstance(database_engine, Sqlite3Engine):
        cur.execute(
            """
            CREATE TRIGGER IF NOT EXISTS partial_state_events_bad_room_id
            BEFORE INSERT ON partial_state_events
            FOR EACH ROW
            BEGIN
                SELECT RAISE(ABORT, 'Incorrect room_id in partial_state_events')
                WHERE EXISTS (
                    SELECT 1 FROM events
                    WHERE events.event_id = NEW.event_id
                       AND events.room_id != NEW.room_id
                );
            END;
            """
        )
    elif isinstance(database_engine, PostgresEngine):
        cur.execute(
            """
            CREATE OR REPLACE FUNCTION check_partial_state_events() RETURNS trigger AS $BODY$
            BEGIN
                IF EXISTS (
                    SELECT 1 FROM events
                    WHERE events.event_id = NEW.event_id
                       AND events.room_id != NEW.room_id
                ) THEN
                    RAISE EXCEPTION 'Incorrect room_id in partial_state_events';
                END IF;
                RETURN NEW;
            END;
            $BODY$ LANGUAGE plpgsql;
            """
        )

        cur.execute(
            """
            CREATE TRIGGER check_partial_state_events BEFORE INSERT OR UPDATE ON partial_state_events
            FOR EACH ROW
            EXECUTE PROCEDURE check_partial_state_events()
            """
        )
    else:
        raise NotImplementedError("Unknown database engine")
