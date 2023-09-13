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

-- If a Synapse deployment made a large jump in versions (from < 1.62.0 to >= 1.70.0)
-- in a single upgrade then it might be possible for the event_push_summary_unique_index
-- to be created in the background from delta 71/02event_push_summary_unique.sql after
-- delta 73/06thread_notifications_thread_id_idx.sql is executed, causing it to
-- not drop the event_push_summary_unique_index index.
--
-- See https://github.com/matrix-org/synapse/issues/14641

-- Stop the index from being scheduled for creation in the background.
DELETE FROM background_updates WHERE update_name = 'event_push_summary_unique_index';

-- The above background job also replaces another index, so ensure that side-effect
-- is applied.
DROP INDEX IF EXISTS event_push_summary_user_rm;

-- Fix deployments which ran the 73/06thread_notifications_thread_id_idx.sql delta
-- before the event_push_summary_unique_index background job was run.
DROP INDEX IF EXISTS event_push_summary_unique_index;
