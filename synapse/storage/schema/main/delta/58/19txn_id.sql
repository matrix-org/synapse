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
--
-- Note: transaction IDs are scoped to the room ID/user ID/access token that was
-- used to make the request.
--
-- Note: The foreign key constraints are ON DELETE CASCADE, as if we delete the
-- events or access token we don't want to try and de-duplicate the event.
CREATE TABLE IF NOT EXISTS event_txn_id (
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

CREATE UNIQUE INDEX IF NOT EXISTS event_txn_id_event_id ON event_txn_id(event_id);
CREATE UNIQUE INDEX IF NOT EXISTS event_txn_id_txn_id ON event_txn_id(room_id, user_id, token_id, txn_id);
CREATE INDEX IF NOT EXISTS event_txn_id_ts ON event_txn_id(inserted_ts);
