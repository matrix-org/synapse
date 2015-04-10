/* Copyright 2014, 2015 OpenMarket Ltd
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

CREATE TABLE IF NOT EXISTS events(
    stream_ordering BIGINT UNSIGNED PRIMARY KEY,
    topological_ordering BIGINT UNSIGNED NOT NULL,
    event_id VARCHAR(150) NOT NULL,
    type VARCHAR(150) NOT NULL,
    room_id VARCHAR(150) NOT NULL,
    content BLOB NOT NULL,
    unrecognized_keys BLOB,
    processed BOOL NOT NULL,
    outlier BOOL NOT NULL,
    depth BIGINT UNSIGNED DEFAULT 0 NOT NULL,
    UNIQUE (event_id)
);

CREATE INDEX IF NOT EXISTS events_stream_ordering ON events (stream_ordering);
CREATE INDEX IF NOT EXISTS events_topological_ordering ON events (topological_ordering);
CREATE INDEX IF NOT EXISTS events_room_id ON events (room_id);


CREATE TABLE IF NOT EXISTS event_json(
    event_id VARCHAR(150) NOT NULL,
    room_id VARCHAR(150) NOT NULL,
    internal_metadata BLOB NOT NULL,
    json BLOB NOT NULL,
    UNIQUE (event_id)
);

CREATE INDEX IF NOT EXISTS event_json_room_id ON event_json(room_id);


CREATE TABLE IF NOT EXISTS state_events(
    event_id VARCHAR(150) NOT NULL,
    room_id VARCHAR(150) NOT NULL,
    type VARCHAR(150) NOT NULL,
    state_key VARCHAR(150) NOT NULL,
    prev_state VARCHAR(150),
    UNIQUE (event_id)
);

CREATE INDEX IF NOT EXISTS state_events_room_id ON state_events (room_id);
CREATE INDEX IF NOT EXISTS state_events_type ON state_events (type);
CREATE INDEX IF NOT EXISTS state_events_state_key ON state_events (state_key);


CREATE TABLE IF NOT EXISTS current_state_events(
    event_id VARCHAR(150) NOT NULL,
    room_id VARCHAR(150) NOT NULL,
    type VARCHAR(150) NOT NULL,
    state_key VARCHAR(150) NOT NULL,
    UNIQUE (event_id),
    UNIQUE (room_id, type, state_key)
);

CREATE INDEX IF NOT EXISTS current_state_events_room_id ON current_state_events (room_id);
CREATE INDEX IF NOT EXISTS current_state_events_type ON current_state_events (type);
CREATE INDEX IF NOT EXISTS current_state_events_state_key ON current_state_events (state_key);

CREATE TABLE IF NOT EXISTS room_memberships(
    event_id VARCHAR(150) NOT NULL,
    user_id VARCHAR(150) NOT NULL,
    sender VARCHAR(150) NOT NULL,
    room_id VARCHAR(150) NOT NULL,
    membership VARCHAR(150) NOT NULL,
    UNIQUE (event_id)
);

CREATE INDEX IF NOT EXISTS room_memberships_room_id ON room_memberships (room_id);
CREATE INDEX IF NOT EXISTS room_memberships_user_id ON room_memberships (user_id);

CREATE TABLE IF NOT EXISTS feedback(
    event_id VARCHAR(150) NOT NULL,
    feedback_type VARCHAR(150),
    target_event_id VARCHAR(150),
    sender VARCHAR(150),
    room_id VARCHAR(150),
    UNIQUE (event_id)
);

CREATE TABLE IF NOT EXISTS topics(
    event_id VARCHAR(150) NOT NULL,
    room_id VARCHAR(150) NOT NULL,
    topic VARCHAR(150) NOT NULL,
    UNIQUE (event_id)
);

CREATE INDEX IF NOT EXISTS topics_room_id ON topics(room_id);

CREATE TABLE IF NOT EXISTS room_names(
    event_id VARCHAR(150) NOT NULL,
    room_id VARCHAR(150) NOT NULL,
    name VARCHAR(150) NOT NULL,
    UNIQUE (event_id)
);

CREATE INDEX IF NOT EXISTS room_names_room_id ON room_names(room_id);

CREATE TABLE IF NOT EXISTS rooms(
    room_id VARCHAR(150) PRIMARY KEY NOT NULL,
    is_public BOOL,
    creator VARCHAR(150)
);

CREATE TABLE IF NOT EXISTS room_hosts(
    room_id VARCHAR(150) NOT NULL,
    host VARCHAR(150) NOT NULL,
    UNIQUE (room_id, host)
);

CREATE INDEX IF NOT EXISTS room_hosts_room_id ON room_hosts (room_id);
