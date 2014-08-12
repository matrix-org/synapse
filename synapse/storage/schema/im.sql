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
CREATE TABLE IF NOT EXISTS rooms(
    room_id TEXT PRIMARY KEY NOT NULL,
    is_public INTEGER,
    creator TEXT
);

CREATE TABLE IF NOT EXISTS room_memberships(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL, -- no foreign key to users table, it could be an id belonging to another home server
    sender TEXT NOT NULL,
    room_id TEXT NOT NULL,
    membership TEXT NOT NULL,
    content TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS messages(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT, 
    room_id TEXT,
    msg_id TEXT,
    content TEXT
);

CREATE TABLE IF NOT EXISTS feedback(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    content TEXT,
    feedback_type TEXT,
    fb_sender_id TEXT,
    msg_id TEXT,
    room_id TEXT,
    msg_sender_id TEXT
);

CREATE TABLE IF NOT EXISTS room_data(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    room_id TEXT NOT NULL,
    type TEXT NOT NULL,
    state_key TEXT NOT NULL,
    content TEXT
);
