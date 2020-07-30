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

-- The reasoning behind the _2 prefix is explained at:
-- https://github.com/matrix-org/synapse/pull/7977#issuecomment-666533910
INSERT INTO background_updates (update_name, progress_json) VALUES
    ('populate_stats_process_rooms_2', '{}');
