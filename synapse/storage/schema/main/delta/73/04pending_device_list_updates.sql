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

-- Stores remote device lists we have received for remote users while a partial
-- join is in progress.
--
-- This allows us to replay any device list updates if it turns out the remote
-- user was in the partially joined room
CREATE TABLE device_lists_remote_pending(
    stream_id BIGINT PRIMARY KEY,
    user_id TEXT NOT NULL,
    device_id TEXT NOT NULL
);

-- We only keep the most recent update for a given user/device pair.
CREATE UNIQUE INDEX device_lists_remote_pending_user_device_id ON device_lists_remote_pending(user_id, device_id);
