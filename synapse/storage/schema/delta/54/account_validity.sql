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

DROP TABLE IF EXISTS account_validity;

-- Track what users are in public rooms.
CREATE TABLE IF NOT EXISTS account_validity (
    user_id TEXT PRIMARY KEY,
    expiration_ts_ms BIGINT NOT NULL,
    email_sent BOOLEAN NOT NULL,
    renewal_token TEXT
);

CREATE INDEX account_validity_email_sent_idx ON account_validity(email_sent, expiration_ts_ms)
CREATE UNIQUE INDEX account_validity_renewal_string_idx ON account_validity(renewal_token)
