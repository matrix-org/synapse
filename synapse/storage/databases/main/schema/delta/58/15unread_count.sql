/* Copyright 2020 The Matrix.org Foundation C.I.C.
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

-- We're hijacking the push actions to store unread messages and unread counts (specified
-- in MSC2654) because doing otherwise would result in either performance issues or
-- reimplementing a consequent bit of the push actions.

-- Add columns to event_push_actions and event_push_actions_staging to track unread
-- messages and calculate unread counts.
ALTER TABLE event_push_actions_staging ADD COLUMN unread SMALLINT;
ALTER TABLE event_push_actions ADD COLUMN unread SMALLINT;

-- Add column to event_push_summary
ALTER TABLE event_push_summary ADD COLUMN unread_count BIGINT;