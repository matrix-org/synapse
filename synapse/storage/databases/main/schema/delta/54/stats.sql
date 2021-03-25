/* Copyright 2018 New Vector Ltd
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

CREATE TABLE stats_stream_pos (
    Lock CHAR(1) NOT NULL DEFAULT 'X' UNIQUE,  -- Makes sure this table only has one row.
    stream_id BIGINT,
    CHECK (Lock='X')
);

INSERT INTO stats_stream_pos (stream_id) VALUES (null);

CREATE TABLE user_stats (
    user_id TEXT NOT NULL,
    ts BIGINT NOT NULL,
    bucket_size INT NOT NULL,
    public_rooms INT NOT NULL,
    private_rooms INT NOT NULL
);

CREATE UNIQUE INDEX user_stats_user_ts ON user_stats(user_id, ts);

CREATE TABLE room_stats (
    room_id TEXT NOT NULL,
    ts BIGINT NOT NULL,
    bucket_size INT NOT NULL,
    current_state_events INT NOT NULL,
    joined_members INT NOT NULL,
    invited_members INT NOT NULL,
    left_members INT NOT NULL,
    banned_members INT NOT NULL,
    state_events INT NOT NULL
);

CREATE UNIQUE INDEX room_stats_room_ts ON room_stats(room_id, ts);

-- cache of current room state; useful for the publicRooms list
CREATE TABLE room_state (
    room_id TEXT NOT NULL,
    join_rules TEXT,
    history_visibility TEXT,
    encryption TEXT,
    name TEXT,
    topic TEXT,
    avatar TEXT,
    canonical_alias TEXT
    -- get aliases straight from the right table
);

CREATE UNIQUE INDEX room_state_room ON room_state(room_id);

CREATE TABLE room_stats_earliest_token (
    room_id TEXT NOT NULL,
    token BIGINT NOT NULL
);

CREATE UNIQUE INDEX room_stats_earliest_token_idx ON room_stats_earliest_token(room_id);

-- Set up staging tables
INSERT INTO background_updates (update_name, progress_json) VALUES
    ('populate_stats_createtables', '{}');

-- Run through each room and update stats
INSERT INTO background_updates (update_name, progress_json, depends_on) VALUES
    ('populate_stats_process_rooms', '{}', 'populate_stats_createtables');

-- Clean up staging tables
INSERT INTO background_updates (update_name, progress_json, depends_on) VALUES
    ('populate_stats_cleanup', '{}', 'populate_stats_process_rooms');
