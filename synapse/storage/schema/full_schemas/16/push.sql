/* Copyright 2015 OpenMarket Ltd
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

CREATE TABLE IF NOT EXISTS rejections(
    event_id VARCHAR(150) NOT NULL,
    reason VARCHAR(150) NOT NULL,
    last_check VARCHAR(150) NOT NULL,
    UNIQUE (event_id)
);

-- Push notification endpoints that users have configured
CREATE TABLE IF NOT EXISTS pushers (
  id BIGINT PRIMARY KEY,
  user_name VARCHAR(150) NOT NULL,
  profile_tag VARCHAR(32) NOT NULL,
  kind VARCHAR(8) NOT NULL,
  app_id VARCHAR(64) NOT NULL,
  app_display_name VARCHAR(64) NOT NULL,
  device_display_name VARCHAR(128) NOT NULL,
  pushkey VARBINARY(512) NOT NULL,
  ts BIGINT NOT NULL,
  lang VARCHAR(8),
  data BLOB,
  last_token TEXT,
  last_success BIGINT,
  failing_since BIGINT,
  UNIQUE (app_id, pushkey)
);

CREATE TABLE IF NOT EXISTS push_rules (
  id BIGINT PRIMARY KEY,
  user_name VARCHAR(150) NOT NULL,
  rule_id VARCHAR(150) NOT NULL,
  priority_class TINYINT NOT NULL,
  priority INTEGER NOT NULL DEFAULT 0,
  conditions VARCHAR(150) NOT NULL,
  actions VARCHAR(150) NOT NULL,
  UNIQUE(user_name, rule_id)
);

CREATE INDEX IF NOT EXISTS push_rules_user_name on push_rules (user_name);

CREATE TABLE IF NOT EXISTS user_filters(
  user_id VARCHAR(150),
  filter_id BIGINT,
  filter_json BLOB
);

CREATE INDEX IF NOT EXISTS user_filters_by_user_id_filter_id ON user_filters(
    user_id, filter_id
);

CREATE TABLE IF NOT EXISTS push_rules_enable (
  id BIGINT PRIMARY KEY,
  user_name VARCHAR(150) NOT NULL,
  rule_id VARCHAR(150) NOT NULL,
  enabled TINYINT,
  UNIQUE(user_name, rule_id)
);

CREATE INDEX IF NOT EXISTS push_rules_enable_user_name on push_rules_enable (user_name);
