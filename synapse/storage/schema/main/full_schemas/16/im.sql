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

/* We used to create tables called room_hosts and feedback,
 * but these are no longer used and are removed in delta 54.
 */

CREATE TABLE IF NOT EXISTS events(
    stream_ordering INTEGER PRIMARY KEY,
    topological_ordering BIGINT NOT NULL,
    event_id TEXT NOT NULL,
    type TEXT NOT NULL,
    room_id TEXT NOT NULL,

    -- 'content' used to be created NULLable, but as of delta 50 we drop that constraint.
    -- the hack we use to drop the constraint doesn't work for an in-memory sqlite
    -- database, which breaks the sytests. Hence, we no longer make it nullable.
    content TEXT,

    unrecognized_keys TEXT,
    processed BOOL NOT NULL,
    outlier BOOL NOT NULL,
    depth BIGINT DEFAULT 0 NOT NULL,
    UNIQUE (event_id)
);

CREATE INDEX events_stream_ordering ON events (stream_ordering);
CREATE INDEX events_topological_ordering ON events (topological_ordering);
CREATE INDEX events_order ON events (topological_ordering, stream_ordering);
CREATE INDEX events_room_id ON events (room_id);
CREATE INDEX events_order_room ON events (
    room_id, topological_ordering, stream_ordering
);


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
    UNIQUE (event_id),
    UNIQUE (room_id, type, state_key)
);

CREATE INDEX current_state_events_room_id ON current_state_events (room_id);
CREATE INDEX current_state_events_type ON current_state_events (type);
CREATE INDEX current_state_events_state_key ON current_state_events (state_key);

CREATE TABLE IF NOT EXISTS room_memberships(
    event_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    sender TEXT NOT NULL,
    room_id TEXT NOT NULL,
    membership TEXT NOT NULL,
    UNIQUE (event_id)
);

CREATE INDEX room_memberships_room_id ON room_memberships (room_id);
CREATE INDEX room_memberships_user_id ON room_memberships (user_id);

CREATE TABLE IF NOT EXISTS topics(
    event_id TEXT NOT NULL,
    room_id TEXT NOT NULL,
    topic TEXT NOT NULL,
    UNIQUE (event_id)
);

CREATE INDEX topics_room_id ON topics(room_id);

CREATE TABLE IF NOT EXISTS room_names(
    event_id TEXT NOT NULL,
    room_id TEXT NOT NULL,
    name TEXT NOT NULL,
    UNIQUE (event_id)
);

CREATE INDEX room_names_room_id ON room_names(room_id);

CREATE TABLE IF NOT EXISTS rooms(
    room_id TEXT PRIMARY KEY NOT NULL,
    is_public BOOL,
    creator TEXT
);
