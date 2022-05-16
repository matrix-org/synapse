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


-- Add a table that keeps track of which "insertion" events need to be backfilled
CREATE TABLE IF NOT EXISTS insertion_event_extremities(
    event_id TEXT NOT NULL,
    room_id TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS insertion_event_extremities_event_id ON insertion_event_extremities(event_id);
CREATE INDEX IF NOT EXISTS insertion_event_extremities_room_id ON insertion_event_extremities(room_id);
