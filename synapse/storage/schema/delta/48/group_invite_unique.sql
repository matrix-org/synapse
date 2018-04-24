DROP INDEX groups_invites_g_idx;
CREATE UNIQUE INDEX groups_invites_g_idx ON group_invites(group_id, user_id);
