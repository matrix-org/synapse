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
    name TEXT,  -- the display name of the room
    avatar_url TEXT,
    short_description TEXT,
    long_description TEXT
);

CREATE UNIQUE INDEX groups_idx ON groups(group_id);


-- list of users the group server thinks are joined
CREATE TABLE group_users (
    group_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    is_admin BOOLEAN NOT NULL,
    is_public BOOLEAN NOT NULL  -- whether the users membership can be seen by everyone
);


CREATE INDEX groups_users_g_idx ON group_users(group_id, user_id);
CREATE INDEX groups_users_u_idx ON group_users(user_id);

-- list of users the group server thinks are invited
CREATE TABLE group_invites (
    group_id TEXT NOT NULL,
    user_id TEXT NOT NULL
);

CREATE INDEX groups_invites_g_idx ON group_invites(group_id, user_id);
CREATE INDEX groups_invites_u_idx ON group_invites(user_id);


CREATE TABLE group_rooms (
    group_id TEXT NOT NULL,
    room_id TEXT NOT NULL,
    is_public BOOLEAN NOT NULL  -- whether the room can be seen by everyone
);

CREATE UNIQUE INDEX groups_rooms_g_idx ON group_rooms(group_id, room_id);
CREATE INDEX groups_rooms_r_idx ON group_rooms(room_id);


-- Rooms to include in the summary
CREATE TABLE group_summary_rooms (
    group_id TEXT NOT NULL,
    room_id TEXT NOT NULL,
    category_id TEXT NOT NULL,
    room_order BIGINT NOT NULL,
    is_public BOOLEAN NOT NULL, -- whether the room should be show to everyone
    UNIQUE (group_id, category_id, room_id, room_order),
    CHECK (room_order > 0)
);

CREATE UNIQUE INDEX group_summary_rooms_g_idx ON group_summary_rooms(group_id, room_id, category_id);


-- Categories to include in the summary
CREATE TABLE group_summary_room_categories (
    group_id TEXT NOT NULL,
    category_id TEXT NOT NULL,
    cat_order BIGINT NOT NULL,
    UNIQUE (group_id, category_id, cat_order),
    CHECK (cat_order > 0)
);

-- The categories in the group
CREATE TABLE group_room_categories (
    group_id TEXT NOT NULL,
    category_id TEXT NOT NULL,
    profile TEXT NOT NULL,
    is_public BOOLEAN NOT NULL, -- whether the category should be show to everyone
    UNIQUE (group_id, category_id)
);

-- The users to include in the group summary
CREATE TABLE group_summary_users (
    group_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    role_id TEXT NOT NULL,
    user_order BIGINT NOT NULL,
    is_public BOOLEAN NOT NULL  -- whether the user should be show to everyone
);

CREATE INDEX group_summary_users_g_idx ON group_summary_users(group_id);

-- The roles to include in the group summary
CREATE TABLE group_summary_roles (
    group_id TEXT NOT NULL,
    role_id TEXT NOT NULL,
    role_order BIGINT NOT NULL,
    UNIQUE (group_id, role_id, role_order),
    CHECK (role_order > 0)
);


-- The roles in a groups
CREATE TABLE group_roles (
    group_id TEXT NOT NULL,
    role_id TEXT NOT NULL,
    profile TEXT NOT NULL,
    is_public BOOLEAN NOT NULL,  -- whether the role should be show to everyone
    UNIQUE (group_id, role_id)
);


-- List of  attestations we've given out and need to renew
CREATE TABLE group_attestations_renewals (
    group_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    valid_until_ms BIGINT NOT NULL
);

CREATE INDEX group_attestations_renewals_g_idx ON group_attestations_renewals(group_id, user_id);
CREATE INDEX group_attestations_renewals_u_idx ON group_attestations_renewals(user_id);
CREATE INDEX group_attestations_renewals_v_idx ON group_attestations_renewals(valid_until_ms);


-- List of attestations we've received from remotes and are interested in.
CREATE TABLE group_attestations_remote (
    group_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    valid_until_ms BIGINT NOT NULL,
    attestation_json TEXT NOT NULL
);

CREATE INDEX group_attestations_remote_g_idx ON group_attestations_remote(group_id, user_id);
CREATE INDEX group_attestations_remote_u_idx ON group_attestations_remote(user_id);
CREATE INDEX group_attestations_remote_v_idx ON group_attestations_remote(valid_until_ms);


-- The group membership for the HS's users
CREATE TABLE local_group_membership (
    group_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    is_admin BOOLEAN NOT NULL,
    membership TEXT NOT NULL,
    is_publicised BOOLEAN NOT NULL,  -- if the user is publicising their membership
    content TEXT NOT NULL
);

CREATE INDEX local_group_membership_u_idx ON local_group_membership(user_id, group_id);
CREATE INDEX local_group_membership_g_idx ON local_group_membership(group_id);


CREATE TABLE local_group_updates (
    stream_id BIGINT NOT NULL,
    group_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    type TEXT NOT NULL,
    content TEXT NOT NULL
);
