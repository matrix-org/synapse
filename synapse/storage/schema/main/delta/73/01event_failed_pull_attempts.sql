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


-- Add a table that keeps track of when we failed to pull an event over
-- federation (via /backfill, `/event`, `/get_missing_events`, etc). This allows
-- us to be more intelligent when we decide to retry (we don't need to fail over
-- and over) and we can process that event in the background so we don't block
-- on it each time.
CREATE TABLE IF NOT EXISTS event_failed_pull_attempts(
    room_id TEXT NOT NULL REFERENCES rooms (room_id),
    event_id TEXT NOT NULL,
    num_attempts INT NOT NULL,
    last_attempt_ts BIGINT NOT NULL,
    last_cause TEXT NOT NULL,
    PRIMARY KEY (room_id, event_id)
);
