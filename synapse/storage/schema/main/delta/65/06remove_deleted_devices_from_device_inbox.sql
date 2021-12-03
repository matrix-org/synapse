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

-- Remove any existing instances of this job running. It's OK to stop and restart this job,
-- as it's just deleting entries from a table - no progress will be lost.
--
-- This is necessary due a similar migration running the job accidentally
-- being included in schema version 64 during v1.47.0rc1,rc2. If a
-- homeserver had updated from Synapse <=v1.45.0 (schema version <=64),
-- then they would have started running this background update already.
-- If that update was still running, then simply inserting it again would
-- cause an SQL failure. So we effectively do an "upsert" here instead.

DELETE FROM background_updates WHERE update_name = 'remove_deleted_devices_from_device_inbox';

INSERT INTO background_updates (ordering, update_name, progress_json) VALUES
  (6506, 'remove_deleted_devices_from_device_inbox', '{}');
