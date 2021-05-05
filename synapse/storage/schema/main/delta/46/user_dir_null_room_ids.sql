/* Copyright 2017 New Vector Ltd
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

-- change the user_directory table to also cover global local user profiles
-- rather than just profiles within specific rooms.

CREATE TABLE user_directory2 (
    user_id TEXT NOT NULL,
    room_id TEXT,
    display_name TEXT,
    avatar_url TEXT
);

INSERT INTO user_directory2(user_id, room_id, display_name, avatar_url)
    SELECT user_id, room_id, display_name, avatar_url from user_directory;

DROP TABLE user_directory;
ALTER TABLE user_directory2 RENAME TO user_directory;

-- create indexes after doing the inserts because that's more efficient.
-- it also means we can give it the same name as the old one without renaming.
CREATE INDEX user_directory_room_idx ON user_directory(room_id);
CREATE UNIQUE INDEX user_directory_user_idx ON user_directory(user_id);
