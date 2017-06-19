/* Copyright 2017 Vector Creations Ltd
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

CREATE TABLE groups (
    group_id TEXT NOT NULL,
    name TEXT,
    avatar_url TEXT,
    short_description TEXT,
    long_description TEXT
);

CREATE UNIQUE INDEX groups_idx ON groups(group_id);


CREATE TABLE group_users (
    group_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    is_admin BOOLEAN NOT NULL,
    is_public BOOLEAN NOT NULL,
    assestation TEXT
);


CREATE INDEX groups_users_g_idx ON group_users(group_id, user_id);
CREATE INDEX groups_users_u_idx ON group_users(user_id);


CREATE TABLE group_invites (
    group_id TEXT NOT NULL,
    user_id TEXT NOT NULL
);

CREATE INDEX groups_invites_g_idx ON group_invites(group_id, user_id);
CREATE INDEX groups_invites_u_idx ON group_invites(user_id);


CREATE TABLE group_rooms (
    group_id TEXT NOT NULL,
    room_id TEXT NOT NULL,
    is_public BOOLEAN NOT NULL
);


CREATE INDEX groups_rooms_g_idx ON group_rooms(group_id, room_id);
CREATE INDEX groups_rooms_r_idx ON group_rooms(room_id);



CREATE TABLE local_group_membership (
    stream_id BIGINT NOT NULL,
    group_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    is_admin BOOLEAN NOT NULL,
    membership TEXT NOT NULL,
    content TEXT NOT NULL
);

CREATE INDEX local_group_membership_u_idx ON local_group_membership(user_id, group_id);
CREATE INDEX local_group_membership_g_idx ON local_group_membership(group_id, group_id);
CREATE INDEX local_group_membership_s_idx ON local_group_membership(user_id, stream_id);


CREATE TABLE group_assestations_renewals (
    group_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    valid_until_ms BIGINT NOT NULL
);

CREATE INDEX group_assestations_renewals_g_idx ON group_assestations_renewals(group_id, user_id);
CREATE INDEX group_assestations_renewals_u_idx ON group_assestations_renewals(user_id);
CREATE INDEX group_assestations_renewals_v_idx ON group_assestations_renewals(valid_until_ms);
