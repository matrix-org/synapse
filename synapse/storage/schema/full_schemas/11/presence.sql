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
CREATE TABLE IF NOT EXISTS presence(
  user_id INTEGER NOT NULL,
  state INTEGER,
  status_msg TEXT,
  mtime INTEGER, -- miliseconds since last state change
  FOREIGN KEY(user_id) REFERENCES users(id)
);

-- For each of /my/ users which possibly-remote users are allowed to see their
-- presence state
CREATE TABLE IF NOT EXISTS presence_allow_inbound(
  observed_user_id INTEGER NOT NULL,
  observer_user_id TEXT, -- a UserID,
  FOREIGN KEY(observed_user_id) REFERENCES users(id)
);

-- For each of /my/ users (watcher), which possibly-remote users are they
-- watching?
CREATE TABLE IF NOT EXISTS presence_list(
  user_id INTEGER NOT NULL,
  observed_user_id TEXT, -- a UserID,
  accepted BOOLEAN,
  FOREIGN KEY(user_id) REFERENCES users(id)
);
