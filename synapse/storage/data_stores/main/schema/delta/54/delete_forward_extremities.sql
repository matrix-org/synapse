/* Copyright 2019 The Matrix.org Foundation C.I.C.
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

-- Start a background job to cleanup extremities that were incorrectly added
-- by bug #5269.
INSERT INTO background_updates (update_name, progress_json) VALUES
  ('delete_soft_failed_extremities', '{}');

DROP TABLE IF EXISTS _extremities_to_check;  -- To make this delta schema file idempotent.
CREATE TABLE _extremities_to_check AS SELECT event_id FROM event_forward_extremities;
CREATE INDEX _extremities_to_check_id ON _extremities_to_check(event_id);
