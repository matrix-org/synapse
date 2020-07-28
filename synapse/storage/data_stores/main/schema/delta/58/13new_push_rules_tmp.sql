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

-- This is a temporary table in which we store the IDs of the users for which we need to
-- serve the new experimental default push rules. The purpose of this table is to help
-- test these new defaults, so it shall be dropped when the experimentation is done.
CREATE TABLE IF NOT EXISTS new_push_rules_users_tmp (
    user_id TEXT PRIMARY KEY
);