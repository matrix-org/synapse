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

CREATE TABLE IF NOT EXISTS application_services_state(
    as_id INTEGER PRIMARY KEY,
    state TEXT,
    last_txn TEXT,
    FOREIGN KEY(as_id) REFERENCES application_services(id)
);

CREATE TABLE IF NOT EXISTS application_services_txns(
    as_id INTEGER NOT NULL,
    txn_id INTEGER NOT NULL,
    content TEXT NOT NULL,
    UNIQUE(as_id, txn_id) ON CONFLICT ROLLBACK
);



