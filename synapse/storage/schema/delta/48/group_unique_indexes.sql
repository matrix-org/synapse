/* Copyright 2018 New Vector Ltd
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

-- remove duplicates from group_users table
DELETE FROM group_users WHERE ctid NOT IN (
   SELECT min(ctid) FROM group_users GROUP BY group_id, user_id
);
DROP INDEX groups_users_g_idx;
CREATE UNIQUE INDEX group_users_g_idx ON group_users(group_id, user_id);

-- remove duplicates from group_invites table
DELETE FROM group_invites WHERE ctid NOT IN (
   SELECT min(ctid) FROM group_invites GROUP BY group_id, user_id
);
DROP INDEX groups_invites_g_idx;
CREATE UNIQUE INDEX group_invites_g_idx ON group_invites(group_id, user_id);

-- rename other indexes to actually match their table names...
ALTER INDEX groups_users_u_idx RENAME TO group_users_u_idx;
ALTER INDEX groups_invites_u_idx RENAME TO group_invites_u_idx;
ALTER INDEX groups_rooms_g_idx RENAME TO group_rooms_g_idx;
ALTER INDEX groups_rooms_r_idx RENAME TO group_rooms_r_idx;
