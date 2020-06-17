/* Copyright 2020 The Matrix.org Foundation C.I.C
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

-- Store the number of unread messages, i.e. messages that triggered either a notify
-- action or a mark_unread one.
ALTER TABLE event_push_summary ADD COLUMN unread_count BIGINT NOT NULL DEFAULT 0;

-- Pre-populate the new column with the count of pending notifications.
-- We expect event_push_summary to be relatively small, so we can do this update
-- synchronously without impacting Synapse's startup time too much.
UPDATE event_push_summary SET unread_count = notif_count;