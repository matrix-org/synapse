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

CREATE TABLE IF NOT EXISTS e2e_fallback_keys_json (
    user_id TEXT NOT NULL, -- The user this fallback key is for.
    device_id TEXT NOT NULL, -- The device this fallback key is for.
    algorithm TEXT NOT NULL, -- Which algorithm this fallback key is for.
    key_id TEXT NOT NULL, -- An id for suppressing duplicate uploads.
    key_json TEXT NOT NULL, -- The key as a JSON blob.
    used BOOLEAN NOT NULL DEFAULT FALSE, -- Whether the key has been used or not.
    CONSTRAINT e2e_fallback_keys_json_uniqueness UNIQUE (user_id, device_id, algorithm)
);
