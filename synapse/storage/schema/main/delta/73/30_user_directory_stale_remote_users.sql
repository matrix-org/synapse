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

-- Table containing a list of remote users whose profiles may have changed
-- since their last update in the user directory.
CREATE TABLE user_directory_stale_remote_users (
    -- The User ID of the remote user whose profile may be stale.
    user_id TEXT NOT NULL PRIMARY KEY,

    -- The server name of the user.
    user_server_name TEXT NOT NULL,

    -- The timestamp (in ms) after which we should next try to request the user's
    -- latest profile.
    next_try_at_ts BIGINT NOT NULL,

    -- The number of retries so far.
    -- 0 means we have not yet attempted to refresh the profile.
    -- Used for calculating exponential backoff.
    retry_counter INTEGER NOT NULL
);

-- Create an index so we can easily query upcoming servers to try.
CREATE INDEX user_directory_stale_remote_users_next_try_idx ON user_directory_stale_remote_users(next_try_at_ts, user_server_name);

-- Create an index so we can easily query upcoming users to try for a particular server.
CREATE INDEX user_directory_stale_remote_users_next_try_by_server_idx ON user_directory_stale_remote_users(user_server_name, next_try_at_ts);
