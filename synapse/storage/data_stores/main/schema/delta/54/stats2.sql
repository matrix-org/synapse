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

-- This delta file gets run after `54/stats.sql` delta.

-- We want to add some indices to the temporary stats table, so we re-insert
-- 'populate_stats_createtables' if we are still processing the rooms update.
INSERT INTO background_updates (update_name, progress_json)
    SELECT 'populate_stats_createtables', '{}'
    WHERE
        'populate_stats_process_rooms' IN (
            SELECT update_name FROM background_updates
        )
        AND 'populate_stats_createtables' NOT IN (  -- don't insert if already exists
            SELECT update_name FROM background_updates
        );
