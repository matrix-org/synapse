/* Copyright 2017 Vector Creations Ltd
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

-- Table keeping track of who shares a room with who. We only keep track
-- of this for local users, so `user_id` is local users only (but we do keep track
-- of which remote users share a room)
CREATE TABLE users_who_share_rooms (
    user_id TEXT NOT NULL,
    other_user_id TEXT NOT NULL,
    room_id TEXT NOT NULL,
    share_private BOOLEAN NOT NULL  -- is the shared room private? i.e. they share a private room
);


CREATE UNIQUE INDEX users_who_share_rooms_u_idx ON users_who_share_rooms(user_id, other_user_id);
CREATE INDEX users_who_share_rooms_r_idx ON users_who_share_rooms(room_id);
CREATE INDEX users_who_share_rooms_o_idx ON users_who_share_rooms(other_user_id);


-- Make sure that we populate the table initially
UPDATE user_directory_stream_pos SET stream_id = NULL;
