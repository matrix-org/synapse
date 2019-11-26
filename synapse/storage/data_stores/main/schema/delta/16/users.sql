-- Convert `access_tokens`.user from rowids to user strings.
-- MUST BE DONE BEFORE REMOVING ID COLUMN FROM USERS TABLE BELOW
CREATE TABLE IF NOT EXISTS new_access_tokens(
    id BIGINT UNSIGNED PRIMARY KEY,
    user_id TEXT NOT NULL,
    device_id TEXT,
    token TEXT NOT NULL,
    last_used BIGINT UNSIGNED,
    UNIQUE(token)
);

INSERT INTO new_access_tokens
    SELECT a.id, u.name, a.device_id, a.token, a.last_used
    FROM access_tokens as a
    INNER JOIN users as u ON u.id = a.user_id;

DROP TABLE access_tokens;

ALTER TABLE new_access_tokens RENAME TO access_tokens;

-- Remove ID column from `users` table
CREATE TABLE IF NOT EXISTS new_users(
    name TEXT,
    password_hash TEXT,
    creation_ts BIGINT UNSIGNED,
    admin BOOL DEFAULT 0 NOT NULL,
    UNIQUE(name)
);

INSERT INTO new_users SELECT name, password_hash, creation_ts, admin FROM users;

DROP TABLE users;

ALTER TABLE new_users RENAME TO users;


-- Remove UNIQUE constraint from `user_ips` table
CREATE TABLE IF NOT EXISTS new_user_ips (
    user_id TEXT NOT NULL,
    access_token TEXT NOT NULL,
    device_id TEXT,
    ip TEXT NOT NULL,
    user_agent TEXT NOT NULL,
    last_seen BIGINT UNSIGNED NOT NULL
);

INSERT INTO new_user_ips
    SELECT user, access_token, device_id, ip, user_agent, last_seen FROM user_ips;

DROP TABLE user_ips;

ALTER TABLE new_user_ips RENAME TO user_ips;

CREATE INDEX IF NOT EXISTS user_ips_user ON user_ips(user_id);
CREATE INDEX IF NOT EXISTS user_ips_user_ip ON user_ips(user_id, access_token, ip);

