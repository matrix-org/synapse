/* Copyright 2019 Matrix.org Foundation CIC
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

-- Track last seen information for a device in the devices table, rather
-- than relying on it being in the user_ips table (which we want to be able
-- to purge old entries from)
ALTER TABLE devices ADD COLUMN last_seen BIGINT;
ALTER TABLE devices ADD COLUMN ip TEXT;
ALTER TABLE devices ADD COLUMN user_agent TEXT;

INSERT INTO background_updates (update_name, progress_json) VALUES
  ('devices_last_seen', '{}');
