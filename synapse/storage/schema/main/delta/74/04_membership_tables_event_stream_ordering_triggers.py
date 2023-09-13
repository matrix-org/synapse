# Copyright 2022 Beeper
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
This migration adds triggers to the room membership tables to enforce consistency.
Triggers cannot be expressed in .sql files, so we have to use a separate file.
"""
from synapse.storage.database import LoggingTransaction
from synapse.storage.engines import BaseDatabaseEngine, PostgresEngine, Sqlite3Engine


def run_create(cur: LoggingTransaction, database_engine: BaseDatabaseEngine) -> None:
    # Complain if the `event_stream_ordering` in membership tables doesn't match
    # the `stream_ordering` row with the same `event_id` in `events`.
    if isinstance(database_engine, Sqlite3Engine):
        for table in (
            "current_state_events",
            "local_current_membership",
            "room_memberships",
        ):
            cur.execute(
                f"""
                CREATE TRIGGER IF NOT EXISTS {table}_bad_event_stream_ordering
                BEFORE INSERT ON {table}
                FOR EACH ROW
                BEGIN
                    SELECT RAISE(ABORT, 'Incorrect event_stream_ordering in {table}')
                    WHERE EXISTS (
                        SELECT 1 FROM events
                        WHERE events.event_id = NEW.event_id
                           AND events.stream_ordering != NEW.event_stream_ordering
                    );
                END;
                """
            )
    elif isinstance(database_engine, PostgresEngine):
        cur.execute(
            """
            CREATE OR REPLACE FUNCTION check_event_stream_ordering() RETURNS trigger AS $BODY$
            BEGIN
                IF EXISTS (
                    SELECT 1 FROM events
                    WHERE events.event_id = NEW.event_id
                       AND events.stream_ordering != NEW.event_stream_ordering
                ) THEN
                    RAISE EXCEPTION 'Incorrect event_stream_ordering';
                END IF;
                RETURN NEW;
            END;
            $BODY$ LANGUAGE plpgsql;
            """
        )

        for table in (
            "current_state_events",
            "local_current_membership",
            "room_memberships",
        ):
            cur.execute(
                f"""
                CREATE TRIGGER check_event_stream_ordering BEFORE INSERT OR UPDATE ON {table}
                FOR EACH ROW
                EXECUTE PROCEDURE check_event_stream_ordering()
                """
            )
    else:
        raise NotImplementedError("Unknown database engine")
