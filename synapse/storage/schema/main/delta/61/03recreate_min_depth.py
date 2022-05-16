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

"""
This migration handles the process of changing the type of `room_depth.min_depth` to
a BIGINT.
"""
from synapse.storage.engines import BaseDatabaseEngine, PostgresEngine
from synapse.storage.types import Cursor


def run_create(cur: Cursor, database_engine: BaseDatabaseEngine, *args, **kwargs):
    if not isinstance(database_engine, PostgresEngine):
        # this only applies to postgres - sqlite does not distinguish between big and
        # little ints.
        return

    # First add a new column to contain the bigger min_depth
    cur.execute("ALTER TABLE room_depth ADD COLUMN min_depth2 BIGINT")

    # Create a trigger which will keep it populated.
    cur.execute(
        """
        CREATE OR REPLACE FUNCTION populate_min_depth2() RETURNS trigger AS $BODY$
            BEGIN
                new.min_depth2 := new.min_depth;
                RETURN NEW;
            END;
        $BODY$ LANGUAGE plpgsql
        """
    )

    cur.execute(
        """
        CREATE TRIGGER populate_min_depth2_trigger BEFORE INSERT OR UPDATE ON room_depth
        FOR EACH ROW
        EXECUTE PROCEDURE populate_min_depth2()
        """
    )

    # Start a bg process to populate it for old rooms
    cur.execute(
        """
       INSERT INTO background_updates (ordering, update_name, progress_json) VALUES
            (6103, 'populate_room_depth_min_depth2', '{}')
       """
    )

    # and another to switch them over once it completes.
    cur.execute(
        """
        INSERT INTO background_updates (ordering, update_name, progress_json, depends_on) VALUES
            (6103, 'replace_room_depth_min_depth', '{}', 'populate_room_depth2')
        """
    )


def run_upgrade(cur: Cursor, database_engine: BaseDatabaseEngine, *args, **kwargs):
    pass
