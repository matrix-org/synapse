/* Copyright 2023 The Matrix.org Foundation C.I.C
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

-- Force the background updates from 06thread_notifications.sql to run in the
-- foreground as code will now require those to be "done".

DELETE FROM background_updates WHERE update_name = 'event_push_backfill_thread_id';

-- Overwrite any null thread_id values.
UPDATE event_push_actions_staging SET thread_id = 'main' WHERE thread_id IS NULL;
UPDATE event_push_actions SET thread_id = 'main' WHERE thread_id IS NULL;

-- Empirically we can end up with entries in the push summary table with both a
-- `NULL` and `main` thread ID, which causes the insert below to fail. We fudge
-- this by deleting any `NULL` rows that have a corresponding `main`.
DELETE FROM event_push_summary AS a WHERE thread_id IS NULL AND EXISTS (
    SELECT 1 FROM event_push_summary AS b
    WHERE b.thread_id = 'main' AND a.user_id = b.user_id AND a.room_id = b.room_id
);
-- Copy the NULL threads to have a 'main' thread ID.
--
-- Note: Some people seem to have duplicate rows with a `NULL` thread ID, in
-- which case we just fudge it with using MAX of the values. The counts *may* be
-- wrong for such rooms, but a) its an edge case, and b) they'll be fixed when
-- the user reads the room.
INSERT INTO event_push_summary (user_id, room_id, notif_count, stream_ordering, unread_count, last_receipt_stream_ordering, thread_id)
    SELECT user_id, room_id, MAX(notif_count), MAX(stream_ordering), MAX(unread_count), MAX(last_receipt_stream_ordering), 'main'
    FROM event_push_summary
    WHERE thread_id IS NULL
    GROUP BY user_id, room_id, thread_id;

DELETE FROM event_push_summary AS a WHERE thread_id IS NULL;

-- Drop the background updates to calculate the indexes used to find null thread_ids.
DELETE FROM background_updates WHERE update_name = 'event_push_actions_thread_id_null';
DELETE FROM background_updates WHERE update_name = 'event_push_summary_thread_id_null';
