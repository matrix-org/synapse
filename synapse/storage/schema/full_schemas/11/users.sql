/* Copyright 2014, 2015 OpenMarket Ltd
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
CREATE TABLE IF NOT EXISTS users(
    name VARCHAR(255),
    password_hash VARBINARY(255),
    creation_ts BIGINT,
    admin BOOL DEFAULT 0 NOT NULL,
    UNIQUE(name)
) ENGINE = INNODB;

CREATE TABLE IF NOT EXISTS access_tokens(
    id INTEGER PRIMARY KEY AUTO_INCREMENT,
    user_id VARCHAR(255) NOT NULL,
    device_id VARCHAR(255),
    token VARCHAR(255) NOT NULL,
    last_used BIGINT,
    UNIQUE(token)
) ENGINE = INNODB;

CREATE TABLE IF NOT EXISTS user_ips (
    user VARCHAR(255) NOT NULL,
    access_token VARCHAR(255) NOT NULL,
    device_id VARCHAR(255),
    ip VARCHAR(255) NOT NULL,
    user_agent VARCHAR(255) NOT NULL,
    last_seen BIGINT NOT NULL,
    UNIQUE (user, access_token, ip, user_agent)
) ENGINE = INNODB;

CREATE INDEX IF NOT EXISTS user_ips_user ON user_ips(user);
