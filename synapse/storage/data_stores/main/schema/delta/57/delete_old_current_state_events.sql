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

-- Add background update to go and delete current state events for rooms the
-- server is no longer in.
--
-- this relies on the 'membership' column of current_state_events, so make sure
-- that's populated first!
INSERT into background_updates (update_name, progress_json, depends_on)
    VALUES ('delete_old_current_state_events', '{}', 'current_state_events_membership');
