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

CREATE TABLE IF NOT EXISTS admin_tokens (
    admin_token TEXT NOT NULL,
    valid_from BIGINT NOT NULL,
    valid_until BIGINT NOT NULL,
    created_by TEXT NOT NULL,
    description TEXT NOT NULL,
    UNIQUE (admin_token)
);

CREATE TABLE IF NOT EXISTS admin_token_permissions (
    admin_token TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    action TEXT NOT NULL,
    allowed BOOL NOT NULL,
    UNIQUE (admin_token, endpoint, action)
);
