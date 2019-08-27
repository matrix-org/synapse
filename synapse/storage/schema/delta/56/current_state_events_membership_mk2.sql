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

-- We add membership to current state so that we don't need to join against
-- room_memberships, which can be surprisingly costly (we do such queries
-- very frequently).
-- This will be null for non-membership events and the content.membership key
-- for membership events. (Will also be null for membership events until the
-- background update job has finished).

INSERT INTO background_updates (update_name, progress_json) VALUES
  ('current_state_events_membership', '{}');
