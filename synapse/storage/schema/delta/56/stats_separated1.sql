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
DROP TABLE IF EXISTS user_stats;
DROP TABLE IF EXISTS room_stats_earliest_tokens;
DROP TABLE IF EXISTS _temp_populate_stats_position;
DROP TABLE IF EXISTS _temp_populate_stats_rooms;
DROP TABLE IF EXISTS stats_stream_pos;

-- Unschedule old background updates if they're still scheduled
DELETE FROM background_updates WHERE update_name IN (
    'populate_stats_createtables',
    'populate_stats_process_rooms',
    'populate_stats_cleanup'
);

----- Create tables for our version of room stats.

-- single-row table to track position of incremental updates
CREATE TABLE IF NOT EXISTS stats_incremental_position (
    -- the stream_id of the last-processed state delta
    state_delta_stream_id BIGINT,

    -- the stream_ordering of the last-processed backfilled event
    -- (this is negative)
    total_events_min_stream_ordering BIGINT,

    -- the stream_ordering of the last-processed normally-created event
    -- (this is positive)
    total_events_max_stream_ordering BIGINT,

    -- If true, this represents the contract agreed upon by the background
    -- population processor.
    -- If false, this is suitable for use by the delta/incremental processor.
    is_background_contract BOOLEAN NOT NULL PRIMARY KEY
);

-- insert a null row and make sure it is the only one.
DELETE FROM stats_incremental_position;
INSERT INTO stats_incremental_position (
    state_delta_stream_id,
    total_events_min_stream_ordering,
    total_events_max_stream_ordering,
    is_background_contract
) VALUES (NULL, NULL, NULL, (0 = 1)), (NULL, NULL, NULL, (1 = 1));

-- represents PRESENT room statistics for a room
CREATE TABLE IF NOT EXISTS room_stats_current (
    room_id TEXT NOT NULL PRIMARY KEY,

    -- These starts cover the time from start_ts...end_ts (in seconds).
    -- Note that end_ts is quantised, and start_ts usually so.
    start_ts BIGINT,
    end_ts BIGINT,

    current_state_events INT NOT NULL DEFAULT 0,
    total_events INT NOT NULL DEFAULT 0,
    joined_members INT NOT NULL DEFAULT 0,
    invited_members INT NOT NULL DEFAULT 0,
    left_members INT NOT NULL DEFAULT 0,
    banned_members INT NOT NULL DEFAULT 0,

    -- If initial background count is still to be performed: NULL
    -- If initial background count has been performed: the maximum delta stream
    --  position that this row takes into account.
    completed_delta_stream_id BIGINT,

    CONSTRAINT timestamp_nullity_equality CHECK ((start_ts IS NULL) = (end_ts IS NULL))
);


-- represents HISTORICAL room statistics for a room
CREATE TABLE IF NOT EXISTS room_stats_historical (
    room_id TEXT NOT NULL,
    -- These stats cover the time from (end_ts - bucket_size)...end_ts (in seconds).
    -- Note that end_ts is quantised, and start_ts usually so.
    end_ts BIGINT NOT NULL,
    bucket_size INT NOT NULL,

    current_state_events INT NOT NULL,
    total_events INT NOT NULL,
    joined_members INT NOT NULL,
    invited_members INT NOT NULL,
    left_members INT NOT NULL,
    banned_members INT NOT NULL,

    PRIMARY KEY (room_id, end_ts)
);

-- We use this index to speed up deletion of ancient room stats.
CREATE INDEX IF NOT EXISTS room_stats_historical_end_ts ON room_stats_historical (end_ts);

-- We don't need an index on (room_id, end_ts) because PRIMARY KEY sorts that
-- out for us. (We would want it to review stats for a particular room.)


-- represents PRESENT statistics for a user
CREATE TABLE IF NOT EXISTS user_stats_current (
    user_id TEXT NOT NULL PRIMARY KEY,

    -- The timestamp that represents the start of the
    start_ts BIGINT,
    end_ts BIGINT,

    public_rooms INT DEFAULT 0 NOT NULL,
    private_rooms INT DEFAULT 0 NOT NULL,

    -- If initial background count is still to be performed: NULL
    -- If initial background count has been performed: the maximum delta stream
    --  position that this row takes into account.
    completed_delta_stream_id BIGINT
);

-- represents HISTORICAL statistics for a user
CREATE TABLE IF NOT EXISTS user_stats_historical (
    user_id TEXT NOT NULL,
    end_ts BIGINT NOT NULL,
    bucket_size INT NOT NULL,

    public_rooms INT NOT NULL,
    private_rooms INT NOT NULL,

    PRIMARY KEY (user_id, end_ts)
);

-- We use this index to speed up deletion of ancient user stats.
CREATE INDEX IF NOT EXISTS user_stats_historical_end_ts ON user_stats_historical (end_ts);

-- We don't need an index on (user_id, end_ts) because PRIMARY KEY sorts that
-- out for us. (We would want it to review stats for a particular user.)
