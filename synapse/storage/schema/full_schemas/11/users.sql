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
    id BIGINT PRIMARY KEY AUTOINCREMENT,
    name VARCHAR(150),
    password_hash VARCHAR(150),
    creation_ts BIGINT,
    admin BOOL DEFAULT 0 NOT NULL,
    UNIQUE(name)
);

CREATE TABLE IF NOT EXISTS access_tokens(
    id BIGINT PRIMARY KEY AUTOINCREMENT,
    user_id VARCHAR(150) NOT NULL,
    device_id VARCHAR(150),
    token VARCHAR(150) NOT NULL,
    last_used BIGINT,
    UNIQUE(token)
);

CREATE TABLE IF NOT EXISTS user_ips (
    user VARCHAR(150) NOT NULL,
    access_token VARCHAR(150) NOT NULL,
    device_id VARCHAR(150),
    ip VARCHAR(150) NOT NULL,
    user_agent VARCHAR(150) NOT NULL,
    last_seen BIGINT NOT NULL,
    UNIQUE (user, access_token, ip, user_agent)
);

CREATE INDEX IF NOT EXISTS user_ips_user ON user_ips(user);
