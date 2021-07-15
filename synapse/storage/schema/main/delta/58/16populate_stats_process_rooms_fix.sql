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
-- This delta file fixes a regression introduced by 58/12room_stats.sql, removing the hacky
-- populate_stats_process_rooms_2 background job and restores the functionality under the
-- original name.
-- See https://github.com/matrix-org/synapse/issues/8238 for details

DELETE FROM background_updates WHERE update_name = 'populate_stats_process_rooms';
UPDATE background_updates SET update_name = 'populate_stats_process_rooms'
    WHERE update_name = 'populate_stats_process_rooms_2';
