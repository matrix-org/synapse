# Copyright 2020 The Matrix.org Foundation C.I.C.
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
This migration rebuilds the device_lists_outbound_last_success table without duplicate
entries, and with a UNIQUE index.
"""

import logging
from io import StringIO

from synapse.storage.engines import BaseDatabaseEngine, PostgresEngine
from synapse.storage.prepare_database import execute_statements_from_stream
from synapse.storage.types import Cursor

logger = logging.getLogger(__name__)


def run_upgrade(*args, **kwargs):
    pass


def run_create(cur: Cursor, database_engine: BaseDatabaseEngine, *args, **kwargs):
    # some instances might already have this index, in which case we can skip this
    if isinstance(database_engine, PostgresEngine):
        cur.execute(
            """
            SELECT 1 FROM pg_class WHERE relkind = 'i'
            AND relname = 'device_lists_outbound_last_success_unique_idx'
            """
        )

        if cur.rowcount:
            logger.info(
                "Unique index exists on device_lists_outbound_last_success: "
                "skipping rebuild"
            )
            return

    logger.info("Rebuilding device_lists_outbound_last_success with unique index")
    execute_statements_from_stream(cur, StringIO(_rebuild_commands))


# there might be duplicates, so the easiest way to achieve this is to create a new
# table with the right data, and renaming it into place

_rebuild_commands = """
DROP TABLE IF EXISTS device_lists_outbound_last_success_new;

CREATE TABLE device_lists_outbound_last_success_new (
    destination TEXT NOT NULL,
    user_id TEXT NOT NULL,
    stream_id BIGINT NOT NULL
);

-- this took about 30 seconds on matrix.org's 16 million rows.
INSERT INTO device_lists_outbound_last_success_new
    SELECT destination, user_id, MAX(stream_id) FROM device_lists_outbound_last_success
    GROUP BY destination, user_id;

-- and this another 30 seconds.
CREATE UNIQUE INDEX device_lists_outbound_last_success_unique_idx
    ON device_lists_outbound_last_success_new (destination, user_id);

DROP TABLE device_lists_outbound_last_success;

ALTER TABLE device_lists_outbound_last_success_new
    RENAME TO device_lists_outbound_last_success;
"""
