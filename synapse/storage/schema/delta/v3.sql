/* Copyright 2014 matrix.org
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

-- SQLite3 doesn't support renaming or dropping columns. We'll have to go the
-- long way round

CREATE TABLE NEW_presence(
  user_id INTEGER NOT NULL,
  presence INTEGER,
  status_msg TEXT,
  last_active INTEGER,
  FOREIGN KEY(user_id) REFERENCES users(id)
);

-- rename the 'state' field to 'presence'; migrate the old 'mtime' field into
-- the new 'last_active' field
INSERT INTO NEW_presence (user_id, presence, status_msg, last_active)
  SELECT user_id, state, status_msg, mtime FROM presence;

DROP TABLE presence;
ALTER TABLE NEW_presence RENAME TO presence;

PRAGMA user_version = 3;
