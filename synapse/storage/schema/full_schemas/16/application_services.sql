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

CREATE TABLE IF NOT EXISTS application_services(
    id BIGINT UNSIGNED PRIMARY KEY,
    url VARCHAR(150),
    token VARCHAR(150),
    hs_token VARCHAR(150),
    sender VARCHAR(150),
    UNIQUE(token)
);

CREATE TABLE IF NOT EXISTS application_services_regex(
    id BIGINT UNSIGNED PRIMARY KEY,
    as_id BIGINT UNSIGNED NOT NULL,
    namespace INTEGER,  /* enum[room_id|room_alias|user_id] */
    regex VARCHAR(150),
    FOREIGN KEY(as_id) REFERENCES application_services(id)
);

CREATE TABLE IF NOT EXISTS application_services_state(
    as_id VARCHAR(150) PRIMARY KEY,
    state VARCHAR(5),
    last_txn INTEGER
);

CREATE TABLE IF NOT EXISTS application_services_txns(
    as_id VARCHAR(150) NOT NULL,
    txn_id INTEGER NOT NULL,
    event_ids BLOB NOT NULL,
    UNIQUE(as_id, txn_id)
);

CREATE INDEX IF NOT EXISTS application_services_txns_id ON application_services_txns (
    as_id
);
