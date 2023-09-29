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

-- Add index so we can easily purge all rows from a given `room_id`
CREATE INDEX IF NOT EXISTS event_failed_pull_attempts_room_id ON event_failed_pull_attempts(room_id);

-- MSC2716 related tables:
-- Add indexes so we can easily purge all rows from a given `room_id`
CREATE INDEX IF NOT EXISTS insertion_events_room_id ON insertion_events(room_id);
CREATE INDEX IF NOT EXISTS batch_events_room_id ON batch_events(room_id);
