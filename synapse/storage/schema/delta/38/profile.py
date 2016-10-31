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
from synapse.storage.engines import PostgresEngine

import logging
import ujson

logger = logging.getLogger(__name__)

CREATE_TABLE = """
CREATE TABLE profiles_extended (
    stream_id BIGINT NOT NULL,
    user_id TEXT NOT NULL,
    persona TEXT NOT NULL,
    key TEXT NOT NULL,
    content TEXT NOT NULL
);

CREATE INDEX profiles_extended_tuple ON profiles_extended(
    user_id, persona, key, stream_id
);
"""

UPDATE_DISPLAY_NAME = """
INSERT INTO profiles_extended (stream_id, user_id, persona, key, content)
SELECT
    1,
    '@' || user_id || ':' || %s,
    'm.display_name',
    '{"rows":["display_name":' || to_json(displayname) || '}]}'
FROM profiles WHERE displayname IS NOT NULL
"""

UPDATE_AVATAR_URL = """
INSERT INTO profiles_extended (stream_id, user_id, persona, key, content)
SELECT
    1,
    '@' || user_id || ':' || %s,
    'm.avatar_url',
    '{"rows":[{"avatar_url":' || to_json(avatar_url) || '}]}'
FROM profiles WHERE avatar_url IS NOT NULL
"""


def run_create(cur, database_engine, *args, **kwargs):
    for statement in get_statements(CREATE_TABLE.splitlines()):
        cur.execute(statement)


def run_upgrade(cur, database_engine, config, *args, **kwargs):
    if isinstance(database_engine, PostgresEngine):
        cur.execute(UPDATE_DISPLAY_NAME, (config.server_name,))
        cur.execute(UPDATE_AVATAR_URL, (config.server_name,))
    else:
        cur.execute(
            "SELECT user_id, displayname FROM profiles WHERE displayname IS NOT NULL"
        )
        displaynames = []
        for user_id, displayname in cur.fetchall():
            displaynames.append((
                1,
                "@%s:%s" % (user_id, config.server_name),
                "default",
                "m.display_name",
                ujson.dumps({"rows": [{"display_name": displayname}]}),
            ))
        cur.executemany(
            "INSERT INTO profiles_extended"
            " (stream_id, user_id, persona, key, content)"
            " VALUES (?,?,?,?,?)",
            displaynames
        )

        cur.execute(
            "SELECT user_id, avatar_url FROM profiles WHERE avatar_url IS NOT NULL"
        )
        avatar_urls = []
        for user_id, avatar_url in cur.fetchall():
            avatar_urls.append((
                1,
                "@%s:%s" % (user_id, config.server_name),
                "default",
                "m.avatar_url",
                ujson.dumps({"rows": [{"avatar_url": avatar_url}]}),
            ))
        cur.executemany(
            "INSERT INTO profiles_extended"
            " (stream_id, user_id, persona, key, content)"
            " VALUES (?,?,?,?,?)",
            avatar_urls
        )
