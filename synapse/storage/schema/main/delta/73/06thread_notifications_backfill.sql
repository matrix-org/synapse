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

-- Forces the background updates from 06thread_notifications.sql to run in the
-- foreground as code will now require those to be "done".

DELETE FROM background_updates WHERE update_name = 'event_push_backfill_thread_id';

-- Overwrite any null thread_id columns.
UPDATE event_push_actions_staging SET thread_id = 'main' WHERE thread_id IS NULL;
UPDATE event_push_actions SET thread_id = 'main' WHERE thread_id IS NULL;
UPDATE event_push_summary SET thread_id = 'main' WHERE thread_id IS NULL;

-- Do not run the event_push_summary_unique_index job if it is pending; the
-- thread_id field will be made required.
DELETE FROM background_updates WHERE update_name = 'event_push_summary_unique_index';
DROP INDEX IF EXISTS event_push_summary_unique_index;
