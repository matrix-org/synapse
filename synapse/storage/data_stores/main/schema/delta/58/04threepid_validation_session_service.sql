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

/* We would like to be able to classify threepid validation sessions
 * by service.
 */

/* We also need to drop the existing sessions as it's not possible to reliably
 * classify them. This will result in UIA sessions needing to be restarted after
 * homeserver upgrade, but the impact of this is rather minimal.
 */

DROP TABLE threepid_validation_session;

/* We choose to recreate the table instead of adding a column as SQLite does not
 * support adding a new NOT NULL column to a table, even if it is empty.
 * https://stackoverflow.com/q/3170634
 */
CREATE TABLE threepid_validation_session (
    session_id TEXT PRIMARY KEY,
    medium TEXT NOT NULL,
    address TEXT NOT NULL,
    client_secret TEXT NOT NULL,
    last_send_attempt BIGINT NOT NULL,
    validated_at BIGINT,
    service TEXT NOT NULL  -- New column
);
