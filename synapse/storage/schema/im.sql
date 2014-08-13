/* Copyright 2014 matrix.org
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
    ordering INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL,
    type TEXT NOT NULL,
--    sender TEXT,
    room_id TEXT,
    content TEXT,
    unrecognized_keys TEXT
);

CREATE TABLE IF NOT EXISTS state_events(
    event_id TEXT NOT NULL,
    room_id TEXT NOT NULL,
    type TEXT NOT NULL,
    state_key TEXT NOT NULL,
    prev_state TEXT
);

CREATE TABLE IF NOT EXISTS current_state(
    event_id TEXT NOT NULL,
    room_id TEXT NOT NULL,
);

CREATE TABLE IF NOT EXISTS room_memberships(
    event_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    sender TEXT NOT NULL,
    room_id TEXT NOT NULL,
    membership TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS feedback(
    event_id TEXT NOT NULL,
    feedback_type TEXT,
    target_event_id TEXT,sudo
    room_id TEXT
);

CREATE TABLE IF NOT EXISTS rooms(
    room_id TEXT PRIMARY KEY NOT NULL,
    is_public INTEGER,
    creator TEXT
);
