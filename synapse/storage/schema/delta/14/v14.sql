CREATE TABLE IF NOT EXISTS push_rules_enable (
  id BIGINT PRIMARY KEY,
  user_name VARCHAR(150) NOT NULL,
  rule_id VARCHAR(150) NOT NULL,
  enabled TINYINT,
  UNIQUE(user_name, rule_id)
);

CREATE INDEX IF NOT EXISTS push_rules_enable_user_name on push_rules_enable (user_name);
