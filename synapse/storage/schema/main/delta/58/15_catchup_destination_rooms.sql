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
-- This schema delta alters the schema to enable 'catching up' remote homeservers
-- after there has been a connectivity problem for any reason.

-- This stores, for each (destination, room) pair, the stream_ordering of the
-- latest event for that destination.
CREATE TABLE IF NOT EXISTS destination_rooms (
  -- the destination in question.
  destination TEXT NOT NULL REFERENCES destinations (destination),
  -- the ID of the room in question
  room_id TEXT NOT NULL REFERENCES rooms (room_id),
  -- the stream_ordering of the event
  stream_ordering BIGINT NOT NULL,
  PRIMARY KEY (destination, room_id)
  -- We don't declare a foreign key on stream_ordering here because that'd mean
  -- we'd need to either maintain an index (expensive) or do a table scan of
  -- destination_rooms whenever we delete an event (also potentially expensive).
  -- In addition to that, a foreign key on stream_ordering would be redundant
  -- as this row doesn't need to refer to a specific event; if the event gets
  -- deleted then it doesn't affect the validity of the stream_ordering here.
);

-- This index is needed to make it so that a deletion of a room (in the rooms
-- table) can be efficient, as otherwise a table scan would need to be performed
-- to check that no destination_rooms rows point to the room to be deleted.
-- Also: it makes it efficient to delete all the entries for a given room ID,
-- such as when purging a room.
CREATE INDEX IF NOT EXISTS destination_rooms_room_id
    ON destination_rooms (room_id);
