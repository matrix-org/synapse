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

-- This stores, for each (destination, room) pair, the event_id and stream_ordering
-- of the latest event to be enqueued for transmission to that destination.
CREATE TABLE IF NOT EXISTS destination_rooms (
  -- the destination in question
  destination TEXT NOT NULL,
  -- the ID of the room in question
  room_id TEXT NOT NULL,
  -- the stream_ordering of the event
  stream_ordering INTEGER,
  -- the event_id of the event
  event_id TEXT NOT NULL,
  PRIMARY KEY (destination, room_id)
);

-- this column tracks the stream_ordering of the event that was most recently
-- successfully transmitted to the destination.
ALTER TABLE destinations
  ADD COLUMN last_successful_stream_ordering INTEGER;
