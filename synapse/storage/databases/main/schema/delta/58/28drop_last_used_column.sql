/*
 * Copyright 2020 The Matrix.org Foundation C.I.C.
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
 -- Dropping last_used column from access_tokens table.

CREATE TABLE access_tokens2 (
    id BIGINT PRIMARY KEY, 
    user_id TEXT NOT NULL, 
    device_id TEXT, 
    token TEXT NOT NULL,
    UNIQUE(token) 
);

INSERT INTO access_tokens2(id, user_id, device_id, token)
    SELECT id, user_id, device_id, token from access_tokens;

DROP TABLE access_tokens;
ALTER TABLE access_tokens2 RENAME TO access_tokens;
