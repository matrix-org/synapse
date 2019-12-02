/* Copyright 2019 New Vector Ltd
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

-- Set up staging tables
INSERT INTO background_updates (update_name, progress_json) VALUES
    ('populate_user_directory_createtables', '{}');

-- Run through each room and update the user directory according to who is in it
INSERT INTO background_updates (update_name, progress_json, depends_on) VALUES
    ('populate_user_directory_process_rooms', '{}', 'populate_user_directory_createtables');

-- Insert all users, if search_all_users is on
INSERT INTO background_updates (update_name, progress_json, depends_on) VALUES
    ('populate_user_directory_process_users', '{}', 'populate_user_directory_process_rooms');

-- Clean up staging tables
INSERT INTO background_updates (update_name, progress_json, depends_on) VALUES
    ('populate_user_directory_cleanup', '{}', 'populate_user_directory_process_users');
