/* Copyright 2014-2016 OpenMarket Ltd
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
    stream_ordering INTEGER PRIMARY KEY AUTOINCREMENT,
    topological_ordering BIGINT NOT NULL,
    event_id TEXT NOT NULL,
    type TEXT NOT NULL,
    room_id TEXT NOT NULL,
    content TEXT NOT NULL,
    unrecognized_keys TEXT,
    processed BOOL NOT NULL,
    outlier BOOL NOT NULL,
    depth BIGINT DEFAULT 0 NOT NULL,
    UNIQUE (event_id)
);

CREATE INDEX events_stream_ordering ON events (stream_ordering);
CREATE INDEX events_topological_ordering ON events (topological_ordering);
CREATE INDEX events_room_id ON events (room_id);


CREATE TABLE IF NOT EXISTS event_json(
    event_id TEXT NOT NULL,
    room_id TEXT NOT NULL,
    internal_metadata TEXT NOT NULL,
    json TEXT NOT NULL,
    UNIQUE (event_id)
);

CREATE INDEX event_json_room_id ON event_json(room_id);


CREATE TABLE IF NOT EXISTS state_events(
    event_id TEXT NOT NULL,
    room_id TEXT NOT NULL,
    type TEXT NOT NULL,
    state_key TEXT NOT NULL,
    prev_state TEXT,
    UNIQUE (event_id)
);

CREATE INDEX state_events_room_id ON state_events (room_id);
CREATE INDEX state_events_type ON state_events (type);
CREATE INDEX state_events_state_key ON state_events (state_key);


CREATE TABLE IF NOT EXISTS current_state_events(
    event_id TEXT NOT NULL,
    room_id TEXT NOT NULL,
    type TEXT NOT NULL,
    state_key TEXT NOT NULL,
    UNIQUE (room_id, type, state_key)
);

CREATE INDEX curr_events_event_id ON current_state_events (event_id);
CREATE INDEX current_state_events_room_id ON current_state_events (room_id);
CREATE INDEX current_state_events_type ON current_state_events (type);
CREATE INDEX current_state_events_state_key ON current_state_events (state_key);

CREATE TABLE IF NOT EXISTS room_memberships(
    event_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    sender TEXT NOT NULL,
    room_id TEXT NOT NULL,
    membership TEXT NOT NULL
);

CREATE INDEX room_memberships_event_id ON room_memberships (event_id);
CREATE INDEX room_memberships_room_id ON room_memberships (room_id);
CREATE INDEX room_memberships_user_id ON room_memberships (user_id);

CREATE TABLE IF NOT EXISTS feedback(
    event_id TEXT NOT NULL,
    feedback_type TEXT,
    target_event_id TEXT,
    sender TEXT,
    room_id TEXT
);

CREATE TABLE IF NOT EXISTS topics(
    event_id TEXT NOT NULL,
    room_id TEXT NOT NULL,
    topic TEXT NOT NULL
);

CREATE INDEX topics_event_id ON topics(event_id);
CREATE INDEX topics_room_id ON topics(room_id);

CREATE TABLE IF NOT EXISTS room_names(
    event_id TEXT NOT NULL,
    room_id TEXT NOT NULL,
    name TEXT NOT NULL
);

CREATE INDEX room_names_event_id ON room_names(event_id);
CREATE INDEX room_names_room_id ON room_names(room_id);

CREATE TABLE IF NOT EXISTS rooms(
    room_id TEXT PRIMARY KEY NOT NULL,
    is_public BOOL,
    creator TEXT
);

CREATE TABLE IF NOT EXISTS room_hosts(
    room_id TEXT NOT NULL,
    host TEXT NOT NULL,
    UNIQUE (room_id, host)
);

CREATE INDEX room_hosts_room_id ON room_hosts (room_id);
