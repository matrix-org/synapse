/* Copyright 2018 New Vector Ltd
 * Copyright 2019 The Matrix.org Foundation C.I.C.
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


----- First clean up from previous versions of room stats.

-- First remove old stats stuff
DROP TABLE IF EXISTS room_stats;
DROP TABLE IF EXISTS user_stats;
DROP TABLE IF EXISTS room_stats_earliest_tokens;
DROP TABLE IF EXISTS _temp_populate_stats_position;
DROP TABLE IF EXISTS _temp_populate_stats_rooms;
DROP TABLE IF EXISTS stats_stream_pos;

-- Unschedule old background updates if they're still scheduled
DELETE FROM background_updates WHERE update_name IN (
    'populate_stats_createtables',
    'populate_stats_process_rooms',
    'populate_stats_cleanup'
);
