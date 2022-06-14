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

ALTER TABLE event_push_actions_staging
  ADD COLUMN thread_id TEXT NOT NULL DEFAULT '';

ALTER TABLE event_push_actions
  ADD COLUMN thread_id TEXT NOT NULL DEFAULT '';

ALTER TABLE event_push_summary
  ADD COLUMN thread_id TEXT NOT NULL DEFAULT '';

-- Update the unique index for `event_push_summary`
INSERT INTO background_updates (ordering, update_name, progress_json) VALUES
  (7003, 'event_push_summary_unique_index2', '{}');
