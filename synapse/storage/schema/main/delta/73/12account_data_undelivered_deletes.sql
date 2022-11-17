/* Copyright 2022 The Matrix.org Foundation C.I.C
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

-- Postgres truncates index names to 64 characters. Otherwise this table
-- would have a better name.
CREATE TABLE IF NOT EXISTS account_data_undelivered_deletes (
    -- The stream_id of the delete in `account_data` or `room_account_data`.
    -- Note that this value is unique across both `account_data` and
    -- `room_account_data` tables.
    stream_id BIGINT NOT NULL,
    -- The account data type identifier.
    type TEXT NOT NULL,
    -- The room ID, if this is referring to `room_account_data`.
    room_id TEXT,
    -- The user that owns this device.
    user_id TEXT NOT NULL,
    -- A device ID that has not yet seen this delete.
    device_id TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(name),
    FOREIGN KEY (room_id) REFERENCES rooms(room_id),
    FOREIGN KEY (user_id, device_id) REFERENCES devices(user_id, device_id)
);

-- Ensure there is only one entry per (stream_id, user_id, device_id) tuple.
CREATE UNIQUE INDEX IF NOT EXISTS
    account_data_undelivered_deletes_stream_id_user_id_device_id
    ON account_data_undelivered_deletes(stream_id, user_id, device_id);

-- This is used to delete any rows for a given
-- (account_data_type, room_id, user_id, device_id) tuple when an account data entry
-- is added again.
CREATE UNIQUE INDEX IF NOT EXISTS
    account_data_undelivered_deletes_type_room_id_user_id_device_id
    ON account_data_undelivered_deletes(type, room_id, user_id, device_id);

-- This is used to delete all rows for a given (user_id, device_id) pair
-- when a device is deleted.
CREATE INDEX IF NOT EXISTS
    account_data_undelivered_deletes_user_id_device_id
    ON account_data_undelivered_deletes(user_id, device_id);