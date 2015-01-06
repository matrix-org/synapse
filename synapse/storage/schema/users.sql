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
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    password_hash TEXT,
    creation_ts INTEGER,
    admin BOOL DEFAULT 0 NOT NULL,
    UNIQUE(name) ON CONFLICT ROLLBACK
);

CREATE TABLE IF NOT EXISTS access_tokens(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    device_id TEXT,
    token TEXT NOT NULL,
    last_used INTEGER,
    FOREIGN KEY(user_id) REFERENCES users(id),
    UNIQUE(token) ON CONFLICT ROLLBACK
);

CREATE TABLE IF NOT EXISTS user_ips (
    user TEXT NOT NULL,
    access_token TEXT NOT NULL,
    device_id TEXT,
    ip TEXT NOT NULL,
    user_agent TEXT NOT NULL,
    last_seen INTEGER NOT NULL,
    CONSTRAINT user_ip UNIQUE (user, access_token, ip, user_agent) ON CONFLICT REPLACE
);

CREATE INDEX IF NOT EXISTS user_ips_user ON user_ips(user);

