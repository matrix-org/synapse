/* Copyright 2020 The Matrix.org Foundation C.I.C
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


-- A map of recent events persisted with transaction IDs. Used to deduplicate
-- send event requests with the same transaction ID.
CREATE TABLE event_txn_id (
    event_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    token_id BIGINT NOT NULL,
    txn_id TEXT NOT NULL,
    inserted_ts BIGINT NOT NULL
);

CREATE UNIQUE INDEX event_txn_id_event_id ON event_txn_id(event_id);
CREATE UNIQUE INDEX event_txn_id_txn_id ON event_txn_id(user_id, token_id, txn_id);
CREATE INDEX event_txn_id_ts ON event_txn_id(inserted_ts);
