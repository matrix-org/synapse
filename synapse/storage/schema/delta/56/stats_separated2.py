# -*- coding: utf-8 -*-
# Copyright 2019 The Matrix.org Foundation C.I.C.
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

# This schema delta will be run after 'stats_separated1.sql' due to lexicographic
# ordering. Note that it MUST be so.
from synapse.storage.engines import PostgresEngine, Sqlite3Engine


def _run_create_generic(stats_type, cursor, database_engine):
    """
    Creates the pertinent (partial, if supported) indices for one kind of stats.
    Args:
        stats_type: "room" or "user" – the type of stats
        cursor: Database Cursor
        database_engine: Database Engine
    """
    if isinstance(database_engine, Sqlite3Engine):
        # even though SQLite >= 3.8 can support partial indices, we won't enable
        # them, in case the SQLite database may be later used on another system.
        # It's also the case that SQLite is only likely to be used in small
        # deployments or testing, where the optimisations gained by use of a
        # partial index are not a big concern.
        cursor.execute(
            """
                CREATE INDEX IF NOT EXISTS %s_stats_current_dirty
                    ON %s_stats_current (end_ts);
            """
            % (stats_type, stats_type)
        )
        cursor.execute(
            """
                CREATE INDEX IF NOT EXISTS %s_stats_not_complete
                    ON %s_stats_current (completed_delta_stream_id, %s_id);
            """
            % (stats_type, stats_type, stats_type)
        )
    elif isinstance(database_engine, PostgresEngine):
        # This partial index helps us with finding dirty stats rows
        cursor.execute(
            """
                CREATE INDEX IF NOT EXISTS %s_stats_current_dirty
                    ON %s_stats_current (end_ts)
                    WHERE end_ts IS NOT NULL;
            """
            % (stats_type, stats_type)
        )
        # This partial index helps us with old collection
        cursor.execute(
            """
                CREATE INDEX IF NOT EXISTS %s_stats_not_complete
                    ON %s_stats_current (%s_id)
                    WHERE completed_delta_stream_id IS NULL;
            """
            % (stats_type, stats_type, stats_type)
        )
    else:
        raise NotImplementedError("Unknown database engine.")


def run_create(cursor, database_engine):
    """
    This function is called as part of the schema delta.
    It will create indices – partial, if supported – for the new 'separated'
    room & user statistics.
    """
    _run_create_generic("room", cursor, database_engine)
    _run_create_generic("user", cursor, database_engine)


def run_upgrade(cur, database_engine, config):
    """
    This function is run on a database upgrade (of a non-empty database).
    We have no need to do anything specific here.
    """
    pass
