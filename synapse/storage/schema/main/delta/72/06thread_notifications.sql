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

-- Add a nullable column for thread ID to the event push actions tables; this
-- will be filled in with a default value for any previously existing rows.
--
-- After migration this can be made non-nullable.

ALTER TABLE event_push_actions_staging ADD COLUMN thread_id TEXT;
ALTER TABLE event_push_actions ADD COLUMN thread_id TEXT;
ALTER TABLE event_push_summary ADD COLUMN thread_id TEXT;

-- Update the unique index for `event_push_summary`.
INSERT INTO background_updates (ordering, update_name, progress_json) VALUES
  (7006, 'event_push_summary_unique_index2', '{}');

INSERT INTO background_updates (ordering, update_name, progress_json, depends_on) VALUES
  (7006, 'event_push_backfill_thread_id', '{}', 'event_push_summary_unique_index2');
