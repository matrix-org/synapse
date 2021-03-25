/* Copyright 2018 New Vector Ltd
 * Copyright 2019 The Matrix.org Foundation C.I.C.
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


----- First clean up from previous versions of room stats.

-- First remove old stats stuff
DROP TABLE IF EXISTS room_stats;
DROP TABLE IF EXISTS room_state;
DROP TABLE IF EXISTS room_stats_state;
DROP TABLE IF EXISTS user_stats;
DROP TABLE IF EXISTS room_stats_earliest_tokens;
DROP TABLE IF EXISTS _temp_populate_stats_position;
DROP TABLE IF EXISTS _temp_populate_stats_rooms;
DROP TABLE IF EXISTS stats_stream_pos;

-- Unschedule old background updates if they're still scheduled
DELETE FROM background_updates WHERE update_name IN (
    'populate_stats_createtables',
    'populate_stats_process_rooms',
    'populate_stats_process_users',
    'populate_stats_cleanup'
);

-- this relies on current_state_events.membership having been populated, so add
-- a dependency on current_state_events_membership.
INSERT INTO background_updates (update_name, progress_json, depends_on) VALUES
    ('populate_stats_process_rooms', '{}', 'current_state_events_membership');

-- this also relies on current_state_events.membership having been populated, but
-- we get that as a side-effect of depending on populate_stats_process_rooms.
INSERT INTO background_updates (update_name, progress_json, depends_on) VALUES
    ('populate_stats_process_users', '{}', 'populate_stats_process_rooms');

----- Create tables for our version of room stats.

-- single-row table to track position of incremental updates
DROP TABLE IF EXISTS stats_incremental_position;
CREATE TABLE stats_incremental_position (
    Lock CHAR(1) NOT NULL DEFAULT 'X' UNIQUE,  -- Makes sure this table only has one row.
    stream_id  BIGINT NOT NULL,
    CHECK (Lock='X')
);

-- insert a null row and make sure it is the only one.
INSERT INTO stats_incremental_position (
    stream_id
) SELECT COALESCE(MAX(stream_ordering), 0) from events;

-- represents PRESENT room statistics for a room
-- only holds absolute fields
DROP TABLE IF EXISTS room_stats_current;
CREATE TABLE room_stats_current (
    room_id TEXT NOT NULL PRIMARY KEY,

    -- These are absolute counts
    current_state_events INT NOT NULL,
    joined_members INT NOT NULL,
    invited_members INT NOT NULL,
    left_members INT NOT NULL,
    banned_members INT NOT NULL,

    local_users_in_room INT NOT NULL,

    -- The maximum delta stream position that this row takes into account.
    completed_delta_stream_id BIGINT NOT NULL
);


-- represents HISTORICAL room statistics for a room
DROP TABLE IF EXISTS room_stats_historical;
CREATE TABLE room_stats_historical (
    room_id TEXT NOT NULL,
    -- These stats cover the time from (end_ts - bucket_size)...end_ts (in ms).
    -- Note that end_ts is quantised.
    end_ts BIGINT NOT NULL,
    bucket_size BIGINT NOT NULL,

    -- These stats are absolute counts
    current_state_events BIGINT NOT NULL,
    joined_members BIGINT NOT NULL,
    invited_members BIGINT NOT NULL,
    left_members BIGINT NOT NULL,
    banned_members BIGINT NOT NULL,
    local_users_in_room BIGINT NOT NULL,

    -- These stats are per time slice
    total_events BIGINT NOT NULL,
    total_event_bytes BIGINT NOT NULL,

    PRIMARY KEY (room_id, end_ts)
);

-- We use this index to speed up deletion of ancient room stats.
CREATE INDEX room_stats_historical_end_ts ON room_stats_historical (end_ts);

-- represents PRESENT statistics for a user
-- only holds absolute fields
DROP TABLE IF EXISTS user_stats_current;
CREATE TABLE user_stats_current (
    user_id TEXT NOT NULL PRIMARY KEY,

    joined_rooms BIGINT NOT NULL,

    -- The maximum delta stream position that this row takes into account.
    completed_delta_stream_id BIGINT NOT NULL
);

-- represents HISTORICAL statistics for a user
DROP TABLE IF EXISTS user_stats_historical;
CREATE TABLE user_stats_historical (
    user_id TEXT NOT NULL,
    end_ts BIGINT NOT NULL,
    bucket_size BIGINT NOT NULL,

    joined_rooms BIGINT NOT NULL,

    invites_sent BIGINT NOT NULL,
    rooms_created BIGINT NOT NULL,
    total_events BIGINT NOT NULL,
    total_event_bytes BIGINT NOT NULL,

    PRIMARY KEY (user_id, end_ts)
);

-- We use this index to speed up deletion of ancient user stats.
CREATE INDEX user_stats_historical_end_ts ON user_stats_historical (end_ts);


CREATE TABLE room_stats_state (
    room_id TEXT NOT NULL,
    name TEXT,
    canonical_alias TEXT,
    join_rules TEXT,
    history_visibility TEXT,
    encryption TEXT,
    avatar TEXT,
    guest_access TEXT,
    is_federatable BOOLEAN,
    topic TEXT
);

CREATE UNIQUE INDEX room_stats_state_room ON room_stats_state(room_id);
