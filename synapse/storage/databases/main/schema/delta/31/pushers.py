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


# Change the last_token to last_stream_ordering now that pushers no longer
# listen on an event stream but instead select out of the event_push_actions
# table.


import logging

logger = logging.getLogger(__name__)


def token_to_stream_ordering(token):
    return int(token[1:].split("_")[0])


def run_create(cur, database_engine, *args, **kwargs):
    logger.info("Porting pushers table, delta 31...")
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS pushers2 (
          id BIGINT PRIMARY KEY,
          user_name TEXT NOT NULL,
          access_token BIGINT DEFAULT NULL,
          profile_tag VARCHAR(32) NOT NULL,
          kind VARCHAR(8) NOT NULL,
          app_id VARCHAR(64) NOT NULL,
          app_display_name VARCHAR(64) NOT NULL,
          device_display_name VARCHAR(128) NOT NULL,
          pushkey TEXT NOT NULL,
          ts BIGINT NOT NULL,
          lang VARCHAR(8),
          data TEXT,
          last_stream_ordering INTEGER,
          last_success BIGINT,
          failing_since BIGINT,
          UNIQUE (app_id, pushkey, user_name)
        )
    """
    )
    cur.execute(
        """SELECT
        id, user_name, access_token, profile_tag, kind,
        app_id, app_display_name, device_display_name,
        pushkey, ts, lang, data, last_token, last_success,
        failing_since
        FROM pushers
    """
    )
    count = 0
    for row in cur.fetchall():
        row = list(row)
        row[12] = token_to_stream_ordering(row[12])
        cur.execute(
            """
                INSERT into pushers2 (
                id, user_name, access_token, profile_tag, kind,
                app_id, app_display_name, device_display_name,
                pushkey, ts, lang, data, last_stream_ordering, last_success,
                failing_since
                ) values (%s)
            """
            % (",".join(["?" for _ in range(len(row))])),
            row,
        )
        count += 1
    cur.execute("DROP TABLE pushers")
    cur.execute("ALTER TABLE pushers2 RENAME TO pushers")
    logger.info("Moved %d pushers to new table", count)


def run_upgrade(cur, database_engine, *args, **kwargs):
    pass
