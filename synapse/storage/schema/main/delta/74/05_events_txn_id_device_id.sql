/* Copyright 2023 The Matrix.org Foundation C.I.C
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

-- For MSC3970, in addition to the (room_id, user_id, token_id, txn_id) -> event_id mapping for each local event,
-- we also store the (room_id, user_id, device_id, txn_id) -> event_id mapping.
--
-- This adds a new event_txn_id_device_id table.

-- A map of recent events persisted with transaction IDs. Used to deduplicate
-- send event requests with the same transaction ID.
--
-- Note: with MSC3970, transaction IDs are scoped to the 
-- room ID/user ID/device ID that was used to make the request.
--
-- Note: The foreign key constraints are ON DELETE CASCADE, as if we delete the
-- event or device we don't want to try and de-duplicate the event.
CREATE TABLE IF NOT EXISTS event_txn_id_device_id (
    event_id TEXT NOT NULL,
    room_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    txn_id TEXT NOT NULL,
    inserted_ts BIGINT NOT NULL,
    FOREIGN KEY (event_id)
        REFERENCES events (event_id) ON DELETE CASCADE,
    FOREIGN KEY (user_id, device_id)
        REFERENCES devices (user_id, device_id) ON DELETE CASCADE
);

-- This ensures that there is only one mapping per event_id.
CREATE UNIQUE INDEX IF NOT EXISTS event_txn_id_device_id_event_id
    ON event_txn_id_device_id(event_id);

-- This ensures that there is only one mapping per (room_id, user_id, device_id, txn_id) tuple.
-- Events are usually looked up using this index.
CREATE UNIQUE INDEX IF NOT EXISTS event_txn_id_device_id_txn_id 
    ON event_txn_id_device_id(room_id, user_id, device_id, txn_id);

-- This table is cleaned up regularly, removing the oldest entries, hence this index.
CREATE INDEX IF NOT EXISTS event_txn_id_device_id_ts
    ON event_txn_id_device_id(inserted_ts);
