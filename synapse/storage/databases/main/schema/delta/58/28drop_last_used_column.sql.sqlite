/*
 * Copyright 2020 The Matrix.org Foundation C.I.C.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

 -- Dropping last_used column from access_tokens table.

CREATE TABLE access_tokens2 (
    id BIGINT PRIMARY KEY, 
    user_id TEXT NOT NULL, 
    device_id TEXT, 
    token TEXT NOT NULL,
    valid_until_ms BIGINT,
    puppets_user_id TEXT,
    last_validated BIGINT,
    UNIQUE(token) 
);

INSERT INTO access_tokens2(id, user_id, device_id, token)
    SELECT id, user_id, device_id, token FROM access_tokens;

DROP TABLE access_tokens;
ALTER TABLE access_tokens2 RENAME TO access_tokens;

CREATE INDEX access_tokens_device_id ON access_tokens (user_id, device_id);


-- Re-adding foreign key reference in event_txn_id table

CREATE TABLE event_txn_id2 (
    event_id TEXT NOT NULL,
    room_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    token_id BIGINT NOT NULL,
    txn_id TEXT NOT NULL,
    inserted_ts BIGINT NOT NULL,
    FOREIGN KEY (event_id)
        REFERENCES events (event_id) ON DELETE CASCADE,
    FOREIGN KEY (token_id)
        REFERENCES access_tokens (id) ON DELETE CASCADE
);

INSERT INTO event_txn_id2(event_id, room_id, user_id, token_id, txn_id, inserted_ts)
    SELECT event_id, room_id, user_id, token_id, txn_id, inserted_ts FROM event_txn_id;

DROP TABLE event_txn_id;
ALTER TABLE event_txn_id2 RENAME TO event_txn_id;

CREATE UNIQUE INDEX IF NOT EXISTS event_txn_id_event_id ON event_txn_id(event_id);
CREATE UNIQUE INDEX IF NOT EXISTS event_txn_id_txn_id ON event_txn_id(room_id, user_id, token_id, txn_id);
CREATE INDEX IF NOT EXISTS event_txn_id_ts ON event_txn_id(inserted_ts);