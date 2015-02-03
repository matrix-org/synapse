/* Copyright 2014 OpenMarket Ltd
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
-- Push notification endpoints that users have configured
CREATE TABLE IF NOT EXISTS pushers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_name TEXT NOT NULL,
  profile_tag varchar(32) NOT NULL,
  kind varchar(8) NOT NULL,
  app_id varchar(64) NOT NULL,
  app_display_name varchar(64) NOT NULL,
  device_display_name varchar(128) NOT NULL,
  pushkey blob NOT NULL,
  ts BIGINT NOT NULL,
  lang varchar(8),
  data blob,
  last_token TEXT,
  last_success BIGINT,
  failing_since BIGINT,
  FOREIGN KEY(user_name) REFERENCES users(name),
  UNIQUE (app_id, pushkey)
);

CREATE TABLE IF NOT EXISTS push_rules (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_name TEXT NOT NULL,
  rule_id TEXT NOT NULL,
  priority_class TINYINT NOT NULL,
  priority INTEGER NOT NULL DEFAULT 0,
  conditions TEXT NOT NULL,
  actions TEXT NOT NULL,
  UNIQUE(user_name, rule_id)
);

CREATE INDEX IF NOT EXISTS push_rules_user_name on push_rules (user_name);
