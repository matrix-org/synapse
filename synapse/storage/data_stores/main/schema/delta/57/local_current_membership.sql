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

-- Stores the latest membership state of local users in rooms, which helps
-- track leaves/bans/etc even if the server has left the room (and so has
-- deleted the room from `current_state_events`).
--
-- This may take a bit of time for large servers (e.g. 40s for matrix.org) but
-- means we avoid a lots of book keeping required to do it as a background
-- update.
--
-- We join against `room_memberships` as `current_state_events.membership` may
-- not have been filled in yet when migrating from old schemas.
CREATE TABLE local_current_membership AS
    SELECT room_id, state_key AS user_id, event_id, room_memberships.membership
    FROM current_state_events
    INNER JOIN users ON (name = state_key)
    INNER JOIN room_memberships USING (room_id, event_id)
    WHERE type = 'm.room.member';

-- Adds the appropriate indices
INSERT INTO background_updates (update_name, progress_json) VALUES
  ('local_current_membership_idx', '{}');

INSERT INTO background_updates (update_name, progress_json) VALUES
  ('local_current_membership_rm_idx', '{}');
