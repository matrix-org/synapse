/* Copyright 2014-2016 OpenMarket Ltd
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

CREATE TABLE IF NOT EXISTS event_forward_extremities(
    event_id TEXT NOT NULL,
    room_id TEXT NOT NULL,
    UNIQUE (event_id, room_id)
);

CREATE INDEX ev_extrem_room ON event_forward_extremities(room_id);
CREATE INDEX ev_extrem_id ON event_forward_extremities(event_id);


CREATE TABLE IF NOT EXISTS event_backward_extremities(
    event_id TEXT NOT NULL,
    room_id TEXT NOT NULL,
    UNIQUE (event_id, room_id)
);

CREATE INDEX ev_b_extrem_room ON event_backward_extremities(room_id);
CREATE INDEX ev_b_extrem_id ON event_backward_extremities(event_id);


CREATE TABLE IF NOT EXISTS event_edges(
    event_id TEXT NOT NULL,
    prev_event_id TEXT NOT NULL,
    room_id TEXT NOT NULL,
    -- We no longer insert prev_state into this table, so all new rows will have
    -- is_state as false.
    is_state BOOL NOT NULL,
    UNIQUE (event_id, prev_event_id, room_id, is_state)
);

CREATE INDEX ev_edges_id ON event_edges(event_id);
CREATE INDEX ev_edges_prev_id ON event_edges(prev_event_id);


CREATE TABLE IF NOT EXISTS room_depth(
    room_id TEXT NOT NULL,
    min_depth INTEGER NOT NULL,
    UNIQUE (room_id)
);

CREATE INDEX room_depth_room ON room_depth(room_id);


create TABLE IF NOT EXISTS event_destinations(
    event_id TEXT NOT NULL,
    destination TEXT NOT NULL,
    delivered_ts BIGINT DEFAULT 0, -- or 0 if not delivered
    UNIQUE (event_id, destination)
);

CREATE INDEX event_destinations_id ON event_destinations(event_id);


CREATE TABLE IF NOT EXISTS state_forward_extremities(
    event_id TEXT NOT NULL,
    room_id TEXT NOT NULL,
    type TEXT NOT NULL,
    state_key TEXT NOT NULL,
    UNIQUE (event_id, room_id)
);

CREATE INDEX st_extrem_keys ON state_forward_extremities(
    room_id, type, state_key
);
CREATE INDEX st_extrem_id ON state_forward_extremities(event_id);


CREATE TABLE IF NOT EXISTS event_auth(
    event_id TEXT NOT NULL,
    auth_id TEXT NOT NULL,
    room_id TEXT NOT NULL,
    UNIQUE (event_id, auth_id, room_id)
);

CREATE INDEX evauth_edges_id ON event_auth(event_id);
CREATE INDEX evauth_edges_auth_id ON event_auth(auth_id);
