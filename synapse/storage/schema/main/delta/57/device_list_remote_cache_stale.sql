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

-- Records whether the server thinks that the remote users cached device lists
-- may be out of date (e.g. if we have received a to device message from a
-- device we don't know about).
CREATE TABLE IF NOT EXISTS device_lists_remote_resync (
    user_id TEXT NOT NULL,
    added_ts BIGINT NOT NULL
);

CREATE UNIQUE INDEX device_lists_remote_resync_idx ON device_lists_remote_resync (user_id);
CREATE INDEX device_lists_remote_resync_ts_idx ON device_lists_remote_resync (added_ts);
