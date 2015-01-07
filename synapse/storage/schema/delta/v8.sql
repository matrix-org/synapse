/* Copyright 2014, 2015 OpenMarket Ltd
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

 CREATE TABLE IF NOT EXISTS event_signatures_2 (
    event_id TEXT,
    signature_name TEXT,
    key_id TEXT,
    signature BLOB,
    CONSTRAINT uniqueness UNIQUE (event_id, signature_name, key_id)
);

INSERT INTO event_signatures_2 (event_id, signature_name, key_id, signature)
SELECT event_id, signature_name, key_id, signature FROM event_signatures;

DROP TABLE event_signatures;
ALTER TABLE event_signatures_2 RENAME TO event_signatures;

CREATE INDEX IF NOT EXISTS event_signatures_id ON event_signatures (
    event_id
);

PRAGMA user_version = 8;