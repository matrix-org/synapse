/* Copyright 2021 The Matrix.org Foundation C.I.C
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

-- Add a table that keeps track of "insertion" events back in the history
-- when we get a "marker" event over the "live" timeline. When navigating the DAG
-- and we hit an event which matches `insertion_prev_event_id`, it should backfill 
-- the "insertion" event and start navigating from there.


CREATE TABLE IF NOT EXISTS insertion_event_extremeties(
    insertion_event_id TEXT NOT NULL,
    room_id TEXT NOT NULL,
    insertion_prev_event_id TEXT NOT NULL,
    UNIQUE (insertion_event_id, room_id, room_id, insertion_prev_event_id)
);

CREATE INDEX IF NOT EXISTS insertion_event_extremeties_insertion_room_id ON insertion_event_extremeties(room_id);
CREATE INDEX IF NOT EXISTS insertion_event_extremeties_insertion_event_id ON insertion_event_extremeties(insertion_event_id);
CREATE INDEX IF NOT EXISTS insertion_event_extremeties_insertion_prev_event_id ON insertion_event_extremeties(insertion_prev_event_id);

CREATE TABLE IF NOT EXISTS chunk_connections(
    event_id TEXT NOT NULL,
    room_id TEXT NOT NULL,
    chunk_id TEXT NOT NULL,
    UNIQUE (event_id, room_id)
);

CREATE INDEX IF NOT EXISTS chunk_connections_insertion_chunk_id ON chunk_connections(chunk_id);
