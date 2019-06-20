/* Copyright 2019 The Matrix.org Foundation C.I.C.
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
CREATE TABLE IF NOT EXISTS threepid_validation_session (
    session_id TEXT PRIMARY KEY,
    medium TEXT NOT NULL,
    address TEXT NOT NULL,
    client_secret TEXT NOT NULL,
    last_send_attempt BIGINT NOT NULL,
    validated_at BIGINT
);

CREATE TABLE IF NOT EXISTS threepid_validation_token (
    token TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    next_link TEXT,
    expires BIGINT NOT NULL
);

CREATE INDEX threepid_validation_token_session_id ON threepid_validation_token(session_id);
