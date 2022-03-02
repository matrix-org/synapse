/* Copyright 2022 The Matrix.org Foundation C.I.C
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

-- rooms which we have done a partial-state-style join to
CREATE TABLE IF NOT EXISTS partial_state_rooms (
    room_id TEXT PRIMARY KEY,
    FOREIGN KEY(room_id) REFERENCES rooms(room_id)
);

-- a list of remote servers we believe are in the room
CREATE TABLE IF NOT EXISTS partial_state_rooms_servers (
    room_id TEXT NOT NULL REFERENCES partial_state_rooms(room_id),
    server_name TEXT NOT NULL,
    UNIQUE(room_id, server_name)
);

-- a list of events with partial state. We can't store this in the `events` table
-- itself, because `events` is meant to be append-only.
CREATE TABLE IF NOT EXISTS partial_state_events (
    -- the room_id is denormalised for efficient indexing (the canonical source is `events`)
    room_id TEXT NOT NULL REFERENCES partial_state_rooms(room_id),
    event_id TEXT NOT NULL REFERENCES events(event_id),
    UNIQUE(event_id)
);

CREATE INDEX IF NOT EXISTS partial_state_events_room_id_idx
     ON partial_state_events (room_id);


