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

from synapse.storage.prepare_database import get_statements

import logging
import ujson

logger = logging.getLogger(__name__)


ALTER_TABLE = """
ALTER TABLE events ADD COLUMN sender TEXT;
ALTER TABLE events ADD COLUMN contains_url BOOLEAN;
"""


def run_create(cur, database_engine, *args, **kwargs):
    for statement in get_statements(ALTER_TABLE.splitlines()):
        cur.execute(statement)

    cur.execute("SELECT MIN(stream_ordering) FROM events")
    rows = cur.fetchall()
    min_stream_id = rows[0][0]

    cur.execute("SELECT MAX(stream_ordering) FROM events")
    rows = cur.fetchall()
    max_stream_id = rows[0][0]

    if min_stream_id is not None and max_stream_id is not None:
        progress = {
            "target_min_stream_id_inclusive": min_stream_id,
            "max_stream_id_exclusive": max_stream_id + 1,
            "rows_inserted": 0,
        }
        progress_json = ujson.dumps(progress)

        sql = (
            "INSERT into background_updates (update_name, progress_json)"
            " VALUES (?, ?)"
        )

        sql = database_engine.convert_param_style(sql)

        cur.execute(sql, ("event_fields_sender_url", progress_json))


def run_upgrade(cur, database_engine, *args, **kwargs):
    pass
