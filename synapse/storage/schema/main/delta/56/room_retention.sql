/* Copyright 2019 New Vector Ltd
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

-- Tracks the retention policy of a room.
-- A NULL max_lifetime or min_lifetime means that the matching property is not defined in
-- the room's retention policy state event.
-- If a room doesn't have a retention policy state event in its state, both max_lifetime
-- and min_lifetime are NULL.
CREATE TABLE IF NOT EXISTS room_retention(
    room_id TEXT,
    event_id TEXT,
    min_lifetime BIGINT,
    max_lifetime BIGINT,

    PRIMARY KEY(room_id, event_id)
);

CREATE INDEX room_retention_max_lifetime_idx on room_retention(max_lifetime);

INSERT INTO background_updates (update_name, progress_json) VALUES
  ('insert_room_retention', '{}');
