/* Copyright 2019 New Vector Ltd
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

-- device signing keys for cross-signing
CREATE TABLE e2e_device_signing_keys (
    user_id TEXT NOT NULL,
    keytype TEXT NOT NULL,
    keydata TEXT NOT NULL,
    ts BIGINT NOT NULL
);

CREATE UNIQUE INDEX e2e_device_signing_keys_idx ON e2e_device_signing_keys(user_id, keytype, ts);

-- devices signatures for cross-signing
CREATE TABLE e2e_device_signatures (
    user_id TEXT NOT NULL,
    key_id TEXT NOT NULL,
    target_user_id TEXT NOT NULL,
    target_device_id TEXT NOT NULL,
    signature TEXT NOT NULL
);

CREATE UNIQUE INDEX e2e_device_signatures_idx ON e2e_device_signatures(user_id, target_user_id, target_device_id);

-- stream of user signature updates
CREATE TABLE user_signature_stream (
    stream_id BIGINT NOT NULL,
    from_user_id TEXT NOT NULL,
    user_ids TEXT NOT NULL
);

CREATE INDEX user_signature_stream_idx ON user_signature_stream(stream_id, from_user_id);

-- device list needs to know which ones are "real" devices, and which ones are
-- just used to avoid collisions
ALTER TABLE devices ADD COLUMN hidden BOOLEAN DEFAULT FALSE;
