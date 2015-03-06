CREATE TABLE IF NOT EXISTS push_rules_enable (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_name TEXT NOT NULL,
  rule_id TEXT NOT NULL,
  enabled TINYINT,
  UNIQUE(user_name, rule_id)
);

CREATE INDEX IF NOT EXISTS push_rules_enable_user_name on push_rules_enable (user_name);
