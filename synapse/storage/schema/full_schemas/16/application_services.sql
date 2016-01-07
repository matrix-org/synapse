/* Copyright 2015, 2016 OpenMarket Ltd
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

CREATE TABLE IF NOT EXISTS application_services(
    id BIGINT PRIMARY KEY,
    url TEXT,
    token TEXT,
    hs_token TEXT,
    sender TEXT,
    UNIQUE(token)
);

CREATE TABLE IF NOT EXISTS application_services_regex(
    id BIGINT PRIMARY KEY,
    as_id BIGINT NOT NULL,
    namespace INTEGER,  /* enum[room_id|room_alias|user_id] */
    regex TEXT,
    FOREIGN KEY(as_id) REFERENCES application_services(id)
);

CREATE TABLE IF NOT EXISTS application_services_state(
    as_id TEXT PRIMARY KEY,
    state VARCHAR(5),
    last_txn INTEGER
);

CREATE TABLE IF NOT EXISTS application_services_txns(
    as_id TEXT NOT NULL,
    txn_id INTEGER NOT NULL,
    event_ids TEXT NOT NULL,
    UNIQUE(as_id, txn_id)
);

CREATE INDEX application_services_txns_id ON application_services_txns (
    as_id
);
