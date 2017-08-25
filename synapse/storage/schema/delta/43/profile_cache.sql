/* Copyright 2017 New Vector Ltd
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


-- A subset of remote users whose profiles we have cached.
-- Whether a user is in this table or not is defined by the storage function
-- `is_subscribed_remote_profile_for_user`
CREATE TABLE remote_profile_cache (
    user_id TEXT NOT NULL,
    displayname TEXT,
    avatar_url TEXT,
    last_check BIGINT NOT NULL
);

CREATE UNIQUE INDEX remote_profile_cache_user_id ON remote_profile_cache(user_id);
CREATE INDEX remote_profile_cache_time ON remote_profile_cache(last_check);
