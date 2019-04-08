-- Drop, copy & recreate pushers table to change unique key
-- Also add access_token column at the same time
CREATE TABLE IF NOT EXISTS pushers2 (
  id BIGINT PRIMARY KEY,
  user_name TEXT NOT NULL,
  access_token BIGINT DEFAULT NULL,
  profile_tag VARCHAR(32) NOT NULL,
  kind VARCHAR(8) NOT NULL,
  app_id VARCHAR(64) NOT NULL,
  app_display_name VARCHAR(64) NOT NULL,
  device_display_name VARCHAR(128) NOT NULL,
  pushkey bytea NOT NULL,
  ts BIGINT NOT NULL,
  lang VARCHAR(8),
  data bytea,
  last_token TEXT,
  last_success BIGINT,
  failing_since BIGINT,
  UNIQUE (app_id, pushkey)
);
INSERT INTO pushers2 (id, user_name, profile_tag, kind, app_id, app_display_name, device_display_name, pushkey, ts, lang, data, last_token, last_success, failing_since)
  SELECT id, user_name, profile_tag, kind, app_id, app_display_name, device_display_name, pushkey, ts, lang, data, last_token, last_success, failing_since FROM pushers;
DROP TABLE pushers;
ALTER TABLE pushers2 RENAME TO pushers;
