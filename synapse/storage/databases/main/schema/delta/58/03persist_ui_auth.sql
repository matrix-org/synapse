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

CREATE TABLE IF NOT EXISTS ui_auth_sessions(
    session_id TEXT NOT NULL,  -- The session ID passed to the client.
    creation_time BIGINT NOT NULL,  -- The time this session was created (epoch time in milliseconds).
    serverdict TEXT NOT NULL,  -- A JSON dictionary of arbitrary data added by Synapse.
    clientdict TEXT NOT NULL,  -- A JSON dictionary of arbitrary data from the client.
    uri TEXT NOT NULL,  -- The URI the UI authentication session is using.
    method TEXT NOT NULL,  -- The HTTP method the UI authentication session is using.
    -- The clientdict, uri, and method make up an tuple that must be immutable
    -- throughout the lifetime of the UI Auth session.
    description TEXT NOT NULL,  -- A human readable description of the operation which caused the UI Auth flow to occur.
    UNIQUE (session_id)
);

CREATE TABLE IF NOT EXISTS ui_auth_sessions_credentials(
    session_id TEXT NOT NULL,  -- The corresponding UI Auth session.
    stage_type TEXT NOT NULL,  -- The stage type.
    result TEXT NOT NULL,  -- The result of the stage verification, stored as JSON.
    UNIQUE (session_id, stage_type),
    FOREIGN KEY (session_id)
        REFERENCES ui_auth_sessions (session_id)
);
