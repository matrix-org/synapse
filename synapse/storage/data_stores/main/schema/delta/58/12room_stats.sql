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

-- Recalculate the stats for all rooms after the fix to joined_members erroneously
-- incrementing on per-room profile changes.

-- Note that the populate_stats_process_rooms background update is already set to
-- run if you're upgrading from Synapse <1.0.0.

-- Additionally, if you've upgraded to v1.18.0 (which doesn't include this fix),
-- this bg job runs, and then update to v1.19.0, you'd end up with only half of
-- your rooms having room stats recalculated after this fix was in place.

-- So we've switched the old `populate_stats_process_rooms` background job to a
-- no-op, and then kick off a bg job with a new name, but with the same
-- functionality as the old one. This effectively restarts the background job
-- from the beginning, without running it twice in a row, supporting both
-- upgrade usecases.
INSERT INTO background_updates (update_name, progress_json) VALUES
    ('populate_stats_process_rooms_2', '{}');
