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

/* We used to create tables called application_services and
 * application_services_regex, but these are no longer used and are removed in
 * delta 54.
 */


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
