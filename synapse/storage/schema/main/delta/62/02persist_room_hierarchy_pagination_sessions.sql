/*
 * Copyright 2021 The Matrix.org Foundation C.I.C.
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

CREATE TABLE IF NOT EXISTS room_hierarchy_pagination_sessions(
    session_id TEXT NOT NULL,  -- The session ID passed to the client.
    creation_time BIGINT NOT NULL,  -- The time this session was created (epoch time in milliseconds).
    room_id TEXT NOT NULL,  -- The room ID of the pagination session.
    suggested_only BOOLEAN NOT NULL, -- Whether to only include suggested rooms/spaces.
    max_depth int, -- The maximum depth to fetch.
    pagination_state TEXT NOT NULL,  -- A JSON dictionary of persisted state.
    UNIQUE (session_id)
);
