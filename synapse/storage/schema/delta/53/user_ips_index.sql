/* Copyright 2018 New Vector Ltd
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

 -- analyze user_ips, to help ensure the correct indices are used
INSERT INTO background_updates (update_name, progress_json) VALUES
  ('user_ips_analyze', '{}');

-- delete duplicates
INSERT INTO background_updates (update_name, progress_json, depends_on) VALUES
  ('user_ips_remove_dupes', '{}', 'user_ips_analyze');

-- add a new unique index to user_ips table
INSERT INTO background_updates (update_name, progress_json, depends_on) VALUES
  ('user_ips_device_unique_index', '{}', 'user_ips_remove_dupes');

-- drop the old original index
INSERT INTO background_updates (update_name, progress_json, depends_on) VALUES
  ('user_ips_drop_nonunique_index', '{}', 'user_ips_device_unique_index');
