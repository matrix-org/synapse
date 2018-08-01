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

-- this is just embarassing :|
ALTER TABLE users_in_pubic_room RENAME TO users_in_public_rooms;

-- this is only 300K rows on matrix.org and takes ~3s to generate the index,
-- so is hopefully not going to block anyone else for that long...
CREATE INDEX users_in_public_rooms_room_idx ON users_in_public_rooms(room_id);
CREATE UNIQUE INDEX users_in_public_rooms_user_idx ON users_in_public_rooms(user_id);
DROP INDEX users_in_pubic_room_room_idx;
DROP INDEX users_in_pubic_room_user_idx;
