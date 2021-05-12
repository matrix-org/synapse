/* Copyright 2019 Werner Sembach
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

-- Groups/communities now get deleted when the last member leaves. This is a one time cleanup to remove old groups/communities that were already empty before that change was made.
DELETE FROM group_attestations_remote WHERE group_id IN (SELECT group_id FROM groups WHERE NOT EXISTS (SELECT group_id FROM group_users WHERE group_id = groups.group_id));
DELETE FROM group_attestations_renewals WHERE group_id IN (SELECT group_id FROM groups WHERE NOT EXISTS (SELECT group_id FROM group_users WHERE group_id = groups.group_id));
DELETE FROM group_invites WHERE group_id IN (SELECT group_id FROM groups WHERE NOT EXISTS (SELECT group_id FROM group_users WHERE group_id = groups.group_id));
DELETE FROM group_roles WHERE group_id IN (SELECT group_id FROM groups WHERE NOT EXISTS (SELECT group_id FROM group_users WHERE group_id = groups.group_id));
DELETE FROM group_room_categories WHERE group_id IN (SELECT group_id FROM groups WHERE NOT EXISTS (SELECT group_id FROM group_users WHERE group_id = groups.group_id));
DELETE FROM group_rooms WHERE group_id IN (SELECT group_id FROM groups WHERE NOT EXISTS (SELECT group_id FROM group_users WHERE group_id = groups.group_id));
DELETE FROM group_summary_roles WHERE group_id IN (SELECT group_id FROM groups WHERE NOT EXISTS (SELECT group_id FROM group_users WHERE group_id = groups.group_id));
DELETE FROM group_summary_room_categories WHERE group_id IN (SELECT group_id FROM groups WHERE NOT EXISTS (SELECT group_id FROM group_users WHERE group_id = groups.group_id));
DELETE FROM group_summary_rooms WHERE group_id IN (SELECT group_id FROM groups WHERE NOT EXISTS (SELECT group_id FROM group_users WHERE group_id = groups.group_id));
DELETE FROM group_summary_users WHERE group_id IN (SELECT group_id FROM groups WHERE NOT EXISTS (SELECT group_id FROM group_users WHERE group_id = groups.group_id));
DELETE FROM local_group_membership WHERE group_id IN (SELECT group_id FROM groups WHERE NOT EXISTS (SELECT group_id FROM group_users WHERE group_id = groups.group_id));
DELETE FROM local_group_updates WHERE group_id IN (SELECT group_id FROM groups WHERE NOT EXISTS (SELECT group_id FROM group_users WHERE group_id = groups.group_id));
DELETE FROM groups WHERE group_id IN (SELECT group_id FROM groups WHERE NOT EXISTS (SELECT group_id FROM group_users WHERE group_id = groups.group_id));
