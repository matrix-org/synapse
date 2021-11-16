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


-- Remove messages from the device_inbox table which were orphaned
-- when a device was deleted using Synapse earlier than 1.47.0.
-- This runs as background task, but may take a bit to finish.

-- The name of this update ending is '_v2' is due to it accidentally
-- being included in schema version 64 during v1.47.0rc1,rc2. If a
-- homeserver had updated from Synapse <=v1.45.0 (schema version <=64),
-- then they would have run the original version of this background update
-- already. So we rename it here, to ensure it is run regardless of upgrade path.

INSERT INTO background_updates (ordering, update_name, progress_json) VALUES
  (6506, 'remove_deleted_devices_from_device_inbox_v2', '{}');
