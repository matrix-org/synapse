/*
 * Copyright 2022 The Matrix.org Foundation C.I.C.
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

-- Login tokens are short-lived tokens that are used for the m.login.token
-- login method, mainly during SSO logins
CREATE TABLE login_tokens (
    token TEXT PRIMARY KEY,
    user_id TEXT NOT NULL, 
    expiry_ts BIGINT NOT NULL,
    used_ts BIGINT,
    auth_provider_id TEXT,
    auth_provider_session_id TEXT
);

-- We're sometimes querying them by their session ID we got from their IDP
CREATE INDEX login_tokens_auth_provider_idx 
    ON login_tokens (auth_provider_id, auth_provider_session_id);

-- We're deleting them by their expiration time
CREATE INDEX login_tokens_expiry_time_idx 
    ON login_tokens (expiry_ts);

