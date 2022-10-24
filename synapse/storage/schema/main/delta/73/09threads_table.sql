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

CREATE TABLE threads (
    room_id TEXT NOT NULL,
    -- The event ID of the root event in the thread.
    thread_id TEXT NOT NULL,
    -- The latest event ID and corresponding topo / stream ordering.
    latest_event_id TEXT NOT NULL,
    topological_ordering BIGINT NOT NULL,
    stream_ordering BIGINT NOT NULL,
    CONSTRAINT threads_uniqueness UNIQUE (room_id, thread_id)
);

CREATE INDEX threads_ordering_idx ON threads(room_id, topological_ordering, stream_ordering);

INSERT INTO background_updates (ordering, update_name, progress_json) VALUES
  (7309, 'threads_backfill', '{}');
